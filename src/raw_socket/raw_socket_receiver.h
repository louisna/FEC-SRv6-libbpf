#ifndef RAW_SOCKET_RECEIVER_H_
#define RAW_SOCKET_RECEIVER_H_

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/seg6.h>

#include "../decoder.h"

int send_raw_socket_recovered(int sfd, const void *repairSymbol_void, struct sockaddr_in6 local_addr);

int send_raw_socket_controller(int sfd, struct sockaddr_in6 decoder, struct sockaddr_in6 encoder, controller_t *controller);

#endif