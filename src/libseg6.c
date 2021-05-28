#ifndef LIBSEG6_H_
#define LIBSEG6_H_

#ifndef VMLINUX_H_
#define VMLINUX_H_
#include <linux/bpf.h>
#endif
#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_
#include <bpf/bpf_helpers.h>
#endif
#include "headers/proto.h"
#include "headers/all.h"

#define TLV_ITERATIONS 16

static __always_inline struct ip6_srh_t *seg6_get_srh(struct __sk_buff *skb)
{
	void *cursor, *data_end;
	struct ip6_srh_t *srh;
	struct ip6_t *ip;
	__u8 *ipver;

	data_end = (void *)(long)skb->data_end;
	cursor = (void *)(long)skb->data;
	ipver = (__u8 *)cursor;

	if ((void *)ipver + sizeof(*ipver) > data_end)
		return 0;

	if ((*ipver >> 4) != 6)
		return 0;

	ip = cursor_advance(cursor, sizeof(*ip));
	if ((void *)ip + sizeof(*ip) > data_end)
		return 0;

	if (ip->next_header != 43)
		return 0;

	srh = cursor_advance(cursor, sizeof(*srh));
	if ((void *)srh + sizeof(*srh) > data_end)
		return 0;

	if (srh->type != 4)
		return 0;

	return srh;
}

static __always_inline int __update_tlv_pad(struct __sk_buff *skb, __u32 new_pad,
		     __u32 old_pad, __u32 pad_off)
{
	int err;

	if (new_pad != old_pad) {
		err = bpf_lwt_seg6_adjust_srh(skb, pad_off,
					  (int) new_pad - (int) old_pad);
		if (err)
			return err;
	}

	if (new_pad > 0) {
		char pad_tlv_buf[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0};
		struct sr6_tlv_t *pad_tlv = (struct sr6_tlv_t *) pad_tlv_buf;

		pad_tlv->type = SR6_TLV_PADDING;
		pad_tlv->len = new_pad - 2;

		err = bpf_lwt_seg6_store_bytes(skb, pad_off,
					       (void *)pad_tlv_buf, new_pad);
		if (err)
			return err;
	}

	return 0;
}

static __always_inline int __is_valid_tlv_boundary(struct __sk_buff *skb, struct ip6_srh_t *srh,
			    __u32 *tlv_off, __u32 *pad_size,
			    __u32 *pad_off)
{
	__u32 srh_off, cur_off;
	int offset_valid = 0;
	int err;

	srh_off = (char *)srh - (char *)(long)skb->data;
	// cur_off = end of segments, start of possible TLVs
	cur_off = srh_off + sizeof(*srh) +
		sizeof(struct ip6_addr_t) * (srh->first_segment + 1);

	*pad_off = 0;

	// we can only go as far as ~10 TLVs due to the BPF max stack size
	#pragma clang loop unroll(full)
	for (int i = 0; i < 10; i++) {
		struct sr6_tlv_t tlv;

		if (cur_off == *tlv_off)
			offset_valid = 1;

		if (cur_off >= srh_off + ((srh->hdrlen + 1) << 3))
			break;

		err = bpf_skb_load_bytes(skb, cur_off, &tlv, sizeof(tlv));
		if (err)
			return err;

		if (tlv.type == SR6_TLV_PADDING) {
			*pad_size = tlv.len + sizeof(tlv);
			*pad_off = cur_off;

			if (*tlv_off == srh_off) {
				*tlv_off = cur_off;
				offset_valid = 1;
			}
			break;

		} else if (tlv.type == SR6_TLV_HMAC) {
			break;
		}

		cur_off += sizeof(tlv) + tlv.len;
	} // we reached the padding or HMAC TLVs, or the end of the SRH

	if (*pad_off == 0)
		*pad_off = cur_off;

	if (*tlv_off == -1)
		*tlv_off = cur_off;
	else if (!offset_valid)
		return -1;

	return 0;
}

static __always_inline int seg6_add_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, __u32 tlv_off,
		 struct sr6_tlv_t *itlv, __u8 tlv_size)
{
	__u32 srh_off = (char *)srh - (char *)(long)skb->data;
	__u8 len_remaining, new_pad;
	__u32 pad_off = 0;
	__u32 pad_size = 0;
	__u32 partial_srh_len;
	int err;

	if (tlv_off != -1)
		tlv_off += srh_off;

	if (itlv->type == SR6_TLV_PADDING || itlv->type == SR6_TLV_HMAC) {
		return -1;
	}

	err = __is_valid_tlv_boundary(skb, srh, &tlv_off, &pad_size, &pad_off);
	if (err) {
		return err;
	}

	err = bpf_lwt_seg6_adjust_srh(skb, tlv_off, sizeof(*itlv) + itlv->len);
	if (err) {
		return err;
	}

	err = bpf_lwt_seg6_store_bytes(skb, tlv_off, (void *)itlv, tlv_size);
	if (err) {
		return err;
	}

	// the following can't be moved inside update_tlv_pad because the
	// bpf verifier has some issues with it
	pad_off += sizeof(*itlv) + itlv->len;
	partial_srh_len = pad_off - srh_off;
	len_remaining = partial_srh_len % 8;
	new_pad = 8 - len_remaining;

	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return __update_tlv_pad(skb, new_pad, pad_size, pad_off);
}

static __always_inline int seg6_delete_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh,
		    __u32 tlv_off)
{
	__u32 srh_off = (char *)srh - (char *)(long)skb->data;
	__u8 len_remaining, new_pad;
	__u32 partial_srh_len;
	__u32 pad_off = 0;
	__u32 pad_size = 0;
	struct sr6_tlv_t tlv;
	int err;

	tlv_off += srh_off;

	err = __is_valid_tlv_boundary(skb, srh, &tlv_off, &pad_size, &pad_off);
	if (err)
		return err;

	err = bpf_skb_load_bytes(skb, tlv_off, &tlv, sizeof(tlv));
	if (err)
		return err;

	err = bpf_lwt_seg6_adjust_srh(skb, tlv_off, -(sizeof(tlv) + tlv.len));
	if (err)
		return err;

	pad_off -= sizeof(tlv) + tlv.len;
	partial_srh_len = pad_off - srh_off;
	len_remaining = partial_srh_len % 8;
	new_pad = 8 - len_remaining;
	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return __update_tlv_pad(skb, new_pad, pad_size, pad_off);
}

static __always_inline int seg6_find_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, __u8 type,
		  __u8 len)
{
	int srh_offset = (char *)srh - (char *)(long)skb->data;
	// initial cursor = end of segments, start of possible TLVs
	int cursor = srh_offset + sizeof(struct ip6_srh_t) +
		((srh->first_segment + 1) << 4);

	#pragma clang loop unroll(full)
	for(int i=0; i < 10; i++) { // TODO limitation
		if (cursor >= srh_offset + ((srh->hdrlen + 1) << 3))
			return -1;

		struct sr6_tlv_t tlv;
		if (bpf_skb_load_bytes(skb, cursor, &tlv, sizeof(struct sr6_tlv_t)))
			return -1;
		//bpf_trace_printk("TLV type=%d len=%d found at offset %d\n", tlv.type, tlv.len, cursor);
	
		if (tlv.type == type && tlv.len + sizeof(struct sr6_tlv_t) == len)
			return cursor;

		cursor += sizeof(tlv) + tlv.len;
	}
	return -1;
}

static __always_inline int seg6_delete_tlv2(struct __sk_buff *skb, struct ip6_srh_t *srh,
		    __u32 tlv_off)
{
	__u32 srh_off = (char *)srh - (char *)(long)skb->data;
	__u8 len_remaining, new_pad;
	__u32 partial_srh_len;
	__u32 pad_off = 0;
	__u32 pad_size = 0;
	struct sr6_tlv_t tlv;
	int err;

	//tlv_off += srh_off;

	err = __is_valid_tlv_boundary(skb, srh, &tlv_off, &pad_size, &pad_off);
	if (err)
		return err;

	err = bpf_skb_load_bytes(skb, tlv_off, &tlv, sizeof(tlv));
	if (err)
		return err;

	err = bpf_lwt_seg6_adjust_srh(skb, tlv_off, -(sizeof(tlv) + tlv.len));
	if (err)
		return err;

	pad_off -= sizeof(tlv) + tlv.len;
	partial_srh_len = pad_off - srh_off;
	len_remaining = partial_srh_len % 8;
	new_pad = 8 - len_remaining;
	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return __update_tlv_pad(skb, new_pad, pad_size, pad_off);
}

static __always_inline int seg6_find_tlv2(struct __sk_buff *skb, struct ip6_srh_t *srh, __u8 *tlv_type, __u8 source_tlv_length, __u8 repair_tlv_length)
		  // TODO: replace all args by structure for typeX, lenX
{
	int srh_offset = (char *)srh - (char *)(long)skb->data;
	// initial cursor = end of segments, start of possible TLVs
	int cursor = srh_offset + sizeof(struct ip6_srh_t) +
		((srh->first_segment + 1) << 4);

	#pragma clang loop unroll(full)
	for(int i=0; i < TLV_ITERATIONS; i++) {
		if (cursor >= srh_offset + ((srh->hdrlen + 1) << 3))
			return -1;

		struct sr6_tlv_t tlv;
		if (bpf_skb_load_bytes(skb, cursor, &tlv, sizeof(struct sr6_tlv_t)))
			return -1;
		//bpf_trace_printk("TLV type=%d len=%d found at offset %d\n", tlv.type, tlv.len, cursor);
		if ((tlv.type == 28 && tlv.len + sizeof(struct sr6_tlv_t) == source_tlv_length) ||
			(tlv.type == 29 && tlv.len + sizeof(struct sr6_tlv_t) == repair_tlv_length)) {
			*tlv_type = tlv.type;
			return cursor;
		}

		cursor += sizeof(tlv) + tlv.len;
	}
	return -1;
}

/*
 * Finds the address where the payload starts. 
 * For now, consider only TCP, UDP and SMTP as transport payload information.
 * Either directly after the Segment Routing header, or after a series of IPv6 headers
 */
static __always_inline void *seg6_find_payload(struct __sk_buff *skb, struct ip6_srh_t *srh) {
	void *data_end = (void *)(long)skb->data_end;
	__u8 nexthdr = srh->nexthdr;
	__u8 hdrlen = (srh->hdrlen + 1) << 3;
	__u16 opt_len;
	int err;

	void *cursor = (void *)srh + hdrlen;
	if (cursor > data_end) {
		return 0;
	}

	if (nexthdr == 6 || nexthdr == 17 || nexthdr == 132) {
		return cursor;
	}

	// First next header is not Transport => iterate
	const int MAX_HEADERS = 10;
	int i;
	for (i = 0; i < MAX_HEADERS; ++i) {
		// Cursor is at the next header already
		if ((void *) cursor + 2 > data_end) {
			return 0;
		}
		if ((void *)cursor + opt_len > data_end)
			return 0;
		opt_len = (1 + (__u16) *((__u8 *) cursor + 1)) << 3;
		nexthdr = (__u16) *((__u8 *)cursor);
		if (nexthdr == 6 || nexthdr == 17 || nexthdr == 132) {
			cursor_advance(cursor, opt_len);
			return cursor;
		}
		cursor_advance(cursor, opt_len);
	}
	return 0; // Not found
}

static inline struct ip6_t *seg6_get_ipv6(struct __sk_buff *skb)
{
	void *cursor, *data_end;
	struct ip6_srh_t *srh;
	struct ip6_t *ip;
	__u8 *ipver;

	data_end = (void *)(long)skb->data_end;
	cursor = (void *)(long)skb->data;
	ipver = (__u8 *)cursor;

	if ((void *)ipver + sizeof(*ipver) > data_end)
		return 0;

	if ((*ipver >> 4) != 6)
		return 0;

	ip = cursor_advance(cursor, sizeof(*ip));
	if ((void *)ip + sizeof(*ip) > data_end)
		return 0;

	return ip;
}

#endif