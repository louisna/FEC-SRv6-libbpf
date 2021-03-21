/**
 * https://blog.apnic.net/2017/10/24/raw-sockets-ipv6/
 * https://github.com/gih900/IPv6--DNS-Frag-Test-Rig/blob/master/dns-server-frag.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/times.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <time.h>
#include "fec_srv6.h"
#include "socket_handler.h"
#include <net/if.h>
#include <netinet/ip6.h>
#include <bits/socket.h>
#include <linux/if_packet.h>

#include <pcap.h>

#define ETH_HDRLEN 14

typedef struct _pktinfo6 {
    struct in6_addr ipi6_addr;
    int ipi6_ifindex;
} pktinfo6;

#define MAXBUF	65536 
#define BACK_PORTNO 53
#define BACK_HOST "dns.google.com"

int portno = BACK_PORTNO ;
char *hostname = BACK_HOST ;

struct sockaddr_in serveraddr4 ;
struct sockaddr_in6 serveraddr6 ;

struct hostent *server ;
time_t t ;
struct response {
  int len ;
  char buf[MAXBUF] ;
  }  dns_response ;
struct in_addr ip4_addr ;
struct in6_addr ip6_addr ;
int proto ;
uint8_t src_mac[6] ;
uint8_t dst_mac[6] ;
char *dns ;
char *host ;
int port ;
char *interface ;
struct sockaddr_ll device; 
struct ifreq ifr ;
int sd ;
char *target, *src_ip, *dst_ip ;
uint8_t *data, *ether_frame ;
int dst_mac_set = 0 ;
int debug = 0 ;
int dontfrag = 1 ;
char *allocate_strmem (int);

struct ip6_srh_t {
  uint8_t nexthdr;
  uint8_t hdrlen;
  uint8_t type;
  uint8_t segments_left;
  uint8_t first_segment;
  uint8_t flags;
  uint16_t tag;
} __attribute__((__packed__));;


struct sr6_tlv_t {
    uint8_t type;
    uint8_t len;
    uint8_t value[0];
} __attribute__((__packed__));

static void *
find_ancillary (struct msghdr *msg, int cmsg_type)
{
  struct cmsghdr *cmsg = NULL;

  for (cmsg = CMSG_FIRSTHDR (msg); cmsg != NULL; cmsg = CMSG_NXTHDR (msg, cmsg)) {
    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == cmsg_type)) {
      return (CMSG_DATA (cmsg));
      }
    }
  return (NULL);
  }


/*
 * allocate_stream
 *
 * Allocate memory for an array of chars.
 */

char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: allocate_strmem length: %i\n", len);
    exit (EXIT_FAILURE);
    }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
    }
  else {
    fprintf (stderr, "ERROR: allocate_strmem malloc failed\n") ;
    exit (EXIT_FAILURE);
    }
  }

/*
 * allocate_ustrmem
 *
 * Allocate memory for an array of unsigned 8 bit ints.
 */

uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: allocate_ustrmem length: %i\n", len);
    exit (EXIT_FAILURE);
    }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
    } 
  else {
    fprintf (stderr, "ERROR: allocate_ustrmem malloc failed\n") ;
    exit (EXIT_FAILURE);
    }
}

uint8_t *ra_mac() {
  int sd;
  int ifindex;
  int len;
  int i;
  uint8_t *inpack;
  struct msghdr msghdr;
  struct iovec iov[2];
  struct ifreq ifr;
  struct nd_router_advert *ra;
  uint8_t *pkt;

  // Allocate memory for various arrays.
  inpack = allocate_ustrmem (IP_MAXPACKET);

  // Prepare msghdr for recvmsg().
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = NULL;
  msghdr.msg_namelen = 0;
  memset (&iov, 0, sizeof (iov));
  iov[0].iov_base = (uint8_t *) inpack;
  iov[0].iov_len = IP_MAXPACKET;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 1;

  msghdr.msg_control = allocate_ustrmem (IP_MAXPACKET);
  msghdr.msg_controllen = IP_MAXPACKET * sizeof (uint8_t);

  /* Request a socket descriptor sd. */
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    perror ("Failed to get socket descriptor ");
    exit (EXIT_FAILURE);
    }

  /* Obtain MAC address of this node. */
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    exit (EXIT_FAILURE);
    }

  /* Retrieve interface index of this node. */
  if ((ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
    }

  /* Bind socket to interface of this node. */
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) < 0) {
    perror ("SO_BINDTODEVICE failed");
    exit (EXIT_FAILURE);
  }

  /* Listen for incoming message from socket sd.
     Keep at it until we get a router advertisement. */
  ra = (struct nd_router_advert *) inpack;
  while (ra->nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT) {
    if ((len = recvmsg (sd, &msghdr, 0)) < 0) {
      perror ("recvmsg failed ");
      exit (EXIT_FAILURE);
      }
    }

  /* got it - all we need is the source mac address */
  pkt = (uint8_t *) inpack;
  for (i=2; i<=7; i++) {
    dst_mac[i-2] = pkt[sizeof (struct nd_router_advert) + i];
    }
  close (sd);
  return (&dst_mac[0]);
}

void open_raw_socket() {
  /* the mac address of the next hop router can be set by -m <mac_addr>
     if it is not set then we need to listen for RA messages and pull
     the mac address of one of them */
   
  if (!dst_mac_set && 0==1) 
    ra_mac();

  /* Allocate memory for various arrays. */
  data = allocate_ustrmem (IP_MAXPACKET); 
  ether_frame = allocate_ustrmem (IP_MAXPACKET); 
  target = allocate_strmem (INET6_ADDRSTRLEN); 
  src_ip = allocate_strmem (INET6_ADDRSTRLEN); 
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN); 
  
  /* Submit request for a socket descriptor to look up interface. */
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { 
    perror ("socket() failed to get socket descriptor for using ioctl() "); 
    exit (EXIT_FAILURE); 
    } 
 
  /* Use ioctl() to look up interface name and get its MAC address. */
  memset (&ifr, 0, sizeof (ifr)); 
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface); 
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) { 
    perror ("ioctl() failed to get source MAC address "); 
    exit (EXIT_FAILURE); 
    } 
  close (sd); 
 
  /* Copy source MAC address into src_mac */
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t)); 
  char *macStr = "08:00:27:78:1f:af";
    sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]);
 
  /* Find interface index from interface name and store index in 
     struct sockaddr_ll device, which will be used as an argument of sendto().  */
  memset (&device, 0, sizeof (device)); 
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) { 
    perror ("if_nametoindex() failed to obtain interface index "); 
    exit (EXIT_FAILURE); 
    } 

  /* Fill out sockaddr_ll. */
  device.sll_family = AF_PACKET; 
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t)); 
  device.sll_halen = 6; 
 
  /* Submit request for a raw socket descriptor. */
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_IPV6)) < 0) { 
    perror ("socket() failed "); 
    exit (EXIT_FAILURE); 
    }
  return;
  } 

int send_coded_packet(struct sockaddr_in6 *srcaddr, struct sockaddr_in6 *dstaddr, const unsigned char *bpf_payload, uint16_t payload_length, const unsigned char *tlv) {
    printf("Coucou\n");
    char out_packet_buffer[4500];
    char payload[4500];
    struct ip6_hdr *iphdr;
    struct udphdr *uhdr;
    struct ip6_srh_t *srh;
    char srh_data[400];
    char *to_buf;
    int uints;
    int datalen;
    int bytes;
    int frame_length;

    /* IPv6 header */
    iphdr = (struct ip6_hdr *)&out_packet_buffer[0];

    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    iphdr->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

    // Next header (8 bits): 43 for routing header
    iphdr->ip6_nxt = 43;

    // Hop limit (8 bits): default to 64
    iphdr->ip6_hops = 64;

    // Source address
    bcopy(&srcaddr->sin6_addr, &(iphdr->ip6_src), 16);

    // Destination address
    bcopy(&dstaddr->sin6_addr, &(iphdr->ip6_dst), 16);

    /* UDP header */
    uhdr = (struct udphdr *)&(payload[0]);
    uhdr->uh_sport = htons(50);
    uhdr->uh_dport = htons(50);
    uhdr->uh_ulen  = htons(payload_length);
    uhdr->uh_sum   = 0; // Do not use the checksum

    /* Copy the repair symbol from the BPF program to the payload buffer */
    bcopy(bpf_payload, &payload[8], payload_length);

    printf("Enter jusqu'ici\n");
    /* IPv6 Segment Routing header */
    srh = (struct ip6_srh_t *)&out_packet_buffer[40]; // After the IPv6 header
    srh->nexthdr       = 17;
    srh->type          = 4; // SRv6
    srh->segments_left = 2; // Manually configured
    srh->first_segment = 1; // Only two segments
    srh->flags         = 0; // Unusued
    srh->tag           = 0; // Unusued
    
    /* Add segments */
    // TODO: for now it is hardcoded
    uint16_t src_bits[8];
    uint16_t dst_bits[8];

    if (inet_pton(AF_INET6, "::1", src_bits) != 1) {
        printf("Error converting source address\n");
        return -1;
    }
    if (inet_pton(AF_INET6, "::2", dst_bits) != 1) {
        printf("Error converting the destination address\n");
        return -1;
    }

    /* Add the segments */
    uint8_t *segment_ptr = (uint8_t *)&out_packet_buffer[40 + 8];
    memcpy(segment_ptr, src_bits, 16);
    memcpy(segment_ptr + 16, dst_bits, 16);

    /* Compute the length of the IPv6 SRH and add padding if needed */
    uint16_t current_srh_len = 2 * 16 + sizeof(struct coding_repair2_t); // Should be 48 bytes
    if (current_srh_len % 8 != 0) {
        printf("ERROR: the size is not a multiple of 16 !\n");
        return -1;
    }
    srh->hdrlen = current_srh_len / 8;

    /* Add the TLV */
    char *tlv_packet = (char *)&out_packet_buffer[40 + 8 + 16 + 16];
    memcpy(tlv_packet, tlv, sizeof(struct coding_repair2_t));

    iphdr->ip6_plen = htons(8 + 16 + 16 + sizeof(struct coding_repair2_t) + 8 + payload_length);

    /* Destination and Source MAC addresses */
    char *macStr = "00:00:00:00:00:00";
    sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac[0], &dst_mac[1], &dst_mac[2], &dst_mac[3], &dst_mac[4], &dst_mac[5]);
    memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    /* Next is ethernet type code (ETH_P_IPV6 for IPv6) */
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;

    /* Assemble to ether frame */
    frame_length = 6 + 6 + 2 + 40 + 8 + 16 + 16 + 8 + 8 + payload_length;

    /* IPv6 header + SRH */
    memcpy(ether_frame + ETH_HDRLEN, iphdr, 40 + 8 + 16 + 16 + 8);

    /* Payload fragment */
    memcpy(ether_frame + ETH_HDRLEN + 40 + 8 + 16 + 16 + 8, payload, 8 + payload_length);

    memcpy(out_packet_buffer + 40 + 8 + 16 + 16 + 16, payload, 8 + payload_length);
    int packet_length = 40 + 8 + 16 + 16 + 16 + 8 + payload_length;

    /* Send ethernet frame to socket */
    if ((bytes = sendto(sd, out_packet_buffer, packet_length, 0, (struct sockaddr *)dstaddr, sizeof(*dstaddr))) <= 0) {
        fprintf(stderr, "Failed to send\n");
        return -1;
    }
    printf("Sent the packet: %d\n", bytes);
    close(sd);

    return 0;
}

int send_repair(char *src_string, char *dst_string, const unsigned char *repair_symbol, uint16_t repair_symbol_length,
                const unsigned char *repair_tlv) {
    struct sockaddr_in6 src;
    struct sockaddr_in6 dst;
    int sockfd;
    socklen_t addrlen, len;
    char str[INET6_ADDRSTRLEN];
    int status;

    /* DEFAULTS */
    interface = "eth0";
    host = "::1";

    // Set "interface" and "host" and "dst_mac" ?
    open_raw_socket();

    if (((status  = inet_pton(AF_INET6, src_string, (void *)(&src.sin6_addr)))) <= 0) {
        if (!status)
            fprintf(stderr, "Not in presentation format");
        else
            fprintf(stderr,  "inet_pton\n");
    }

    src.sin6_family = AF_INET6;
    src.sin6_port = htons(50); // So ?

    if (inet_ntop(AF_INET6, (void *)&src.sin6_addr, str, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("L'adresse devient %s\n", str);

    status = inet_pton(AF_INET6, dst_string, (void *)&(dst.sin6_addr));

    send_coded_packet(&src, &dst, repair_symbol, repair_symbol_length, repair_tlv);
    return 0;
}