#ifndef RAW_SOCKET_SENDER_H_
#define RAW_SOCKET_SENDER_H_

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/seg6.h>

#include "../encoder.h"

int send_raw_socket(int sfd, const struct repairSymbol_t *repairSymbol, struct sockaddr_in6 src, struct sockaddr_in6 dst);

#endif