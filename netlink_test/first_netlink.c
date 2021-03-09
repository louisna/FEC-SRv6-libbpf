/**
 * @author: Louis Navarre <louisnavarre@hotmail.com> (UCLouvain)
 * @date: 2021.03.08
 * The following code is highly inspired from the block of Oleg Kutkov:
 * https://olegkutkov.me/2019/08/29/modifying-linux-network-routes-using-netlink/
 * Consulted 2021.03.08
 **/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

/* Open netlink socket */
int open_netlink()
{
    struct sockaddr_nl saddr;

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (sock < 0) {
        perror("Failed to open netlink socket");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));

    return sock;
}

/* Helper structure for ip address data and attributes */
typedef struct {
    char family;
    unsigned char bitlen;
    unsigned char data[sizeof(struct in6_addr)];
} _inet_addr;

/* */

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* Add new data to rtattr */
int rtattr_add(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen) {
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        fprintf(stderr, "rtattr_add error: message exceeded bound of %d\n", maxlen);
        return -1;
    }

    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len; 
    printf("#1: %d\n", alen);
    if (alen) {
        memcpy(RTA_DATA(rta), data, alen);
    }

    printf("#2\n");

    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

    return 0;
}

int do_route(int sock, int cmd, int flags, _inet_addr *dst, _inet_addr *gw, int def_gw, int if_idx) {
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[4096];
    } nl_request;

    /* Initialize request structure */
    nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nl_request.n.nlmsg_flags = NLM_F_REQUEST | flags;
    nl_request.n.nlmsg_type = cmd;
    nl_request.r.rtm_family = dst->family;
    nl_request.r.rtm_table = RT_TABLE_MAIN;
    nl_request.r.rtm_scope = RT_SCOPE_NOWHERE;

    /* Set additional flags if NOT deleting route */
    if (cmd != RTM_DELROUTE) {
        nl_request.r.rtm_protocol = RTPROT_BOOT;
        nl_request.r.rtm_type = RTN_UNICAST;
    }

    nl_request.r.rtm_family = dst->family;
    nl_request.r.rtm_dst_len = dst->bitlen;

    /* Select scope, for simplicity we supports here only IPv6 and IPv4 */
    if (nl_request.r.rtm_family == AF_INET6) {
        nl_request.r.rtm_scope = RT_SCOPE_UNIVERSE;
    } else {
        nl_request.r.rtm_scope = RT_SCOPE_LINK;
    }
    printf("Set gw\n");
    /* Set gateway */
    if (gw->bitlen != 0) {
        rtattr_add(&nl_request.n, sizeof(nl_request), RTA_GATEWAY, &gw->data, gw->bitlen / 8);
        nl_request.r.rtm_scope = 0;
        nl_request.r.rtm_family = gw->family;
    }
    printf("Set addr\n");
    /* Don't set destination and interface in case of default gateways */
    if (!def_gw) {
        /* Set destination network */
        printf("1, %d\n", dst->bitlen);
        rtattr_add(&nl_request.n, sizeof(nl_request), /*RTA_NEWDST*/ RTA_DST, &dst->data, dst->bitlen / 8);
        printf("2\n");
        /* Set interface */
        rtattr_add(&nl_request.n, sizeof(nl_request), RTA_OIF, &if_idx, sizeof(int));
    }

    printf("Send message\n");

    /* Send message to the netlink */
    return send(sock, &nl_request, sizeof(nl_request), 0);
}

/* Simple parser of the string IP address
 */
int read_addr(char *addr, _inet_addr *res) {
    if (strchr(addr, ':')) {
        res->family = AF_INET6;
        res->bitlen = 128;
    } else {
        res->family = AF_INET;
        res->bitlen = 32;
    }

    return inet_pton(res->family, addr, res->data);
}

#define NEXT_CMD_ARG() do { argv++; if (--argc <= 0) exit(-1); } while(0)

int main(int argc, char **argv) {
    int default_gw = 0;
    int if_idx = 0;
    int nl_sock;
    _inet_addr to_addr = { 0 };
    _inet_addr gw_addr = { 0 };

    int nl_cmd;
    int nl_flags;

    /* Parse command line arguments */
    while (argc > 0) {
        if (strcmp(*argv, "add") == 0) {
            nl_cmd = RTM_NEWROUTE;
            nl_flags = NLM_F_CREATE | NLM_F_EXCL;

        } else if (strcmp(*argv, "del") == 0) {
            nl_cmd = RTM_DELROUTE;
            nl_flags = 0;

        } else if (strcmp(*argv, "to") == 0) {
            NEXT_CMD_ARG(); /* skip "to" and jump to the actual destination addr */

            if (read_addr(*argv, &to_addr) != 1) {
                fprintf(stderr, "Failed to parse destination network %s\n", *argv);
                exit(-1);
            }

            printf("Address; %s\n", *argv);

        } else if (strcmp(*argv, "dev") == 0) {
            NEXT_CMD_ARG(); /* skip "dev" */

            if_idx = if_nametoindex(*argv);
            printf("Interface: %s becomes: %d\n", *argv, if_idx);

        } else if (strcmp(*argv, "via") == 0) {
            NEXT_CMD_ARG(); /* skip "via"*/

            /* Instead of gw address user can set here keyword "default" */
            /* Try to read this keyword and jump to the actual gateway addr */
            if (strcmp(*argv, "default") == 0) {
                default_gw = 1;
                NEXT_CMD_ARG();
            }

            if (read_addr(*argv, &gw_addr) != 1) {
                fprintf(stderr, "Failed to parse gateway address %s\n", *argv);
                exit(-1);
            }
        }

        argc--; argv++;
    }

    nl_sock = open_netlink();

    if (nl_sock < 0) {
        exit(-1);
    }

    int err = do_route(nl_sock, nl_cmd, nl_flags, &to_addr, &gw_addr, default_gw, if_idx);
    printf("Value of err: %d\n", err);

    close (nl_sock);

    return 0;
}