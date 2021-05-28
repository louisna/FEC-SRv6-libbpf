#!/bin/bash

sysctl -w net.core.rmem_default=524287
sysctl -w net.core.wmem_default=524287
sysctl -w net.core.rmem_max=524287
sysctl -w net.core.wmem_max=524287
sysctl -w net.core.optmem_max=524287
sysctl -w net.core.netdev_max_backlog=300000
sysctl -w net.ipv4.tcp_rmem="10000000 10000000 10000000"
sysctl -w net.ipv4.tcp_wmem="10000000 10000000 10000000"
sysctl -w net.ipv4.tcp_mem="10000000 10000000 10000000"
sysctl net.ipv6.conf.all.forwarding=1
sysctl net.ipv6.conf.all.seg6_enabled=1
sysctl net.ipv6.conf.r-eth1.seg6_enabled=1

ethtool -K r-eth1 gro off
ethtool -K r-eth1 gso off
ethtool -K r-eth1 tx off
ethtool -K r-eth1 rx off

# ixgbe trick to prevent unnecessary calls to ipv6_find_hdr()
# Improve perfs by ~1Mpps in rx-pause=off mode. No effect (currently)
# in rx-pause=on mode.
ethtool -K r-eth1 rx-ntuple-filter on

# Also improve perfs in rx-pause=off
ethtook -G r-eth1 tx 1024
ethtool -C r-eth1 rx-usecs 30

ip -6 ad ad fc00::44/64 dev r-eth1

for i in $(seq 38 45); do echo 7 > /proc/irq/$i/smp_affinity_list; done