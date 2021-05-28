#!/bin/bash

sysctl -w net.core.rmem_default=2621440
sysctl -w net.core.wmem_default=2621440
sysctl -w net.core.rmem_max=2621440
sysctl -w net.core.wmem_max=2621440
sysctl -w net.core.optmem_max=2621440
sysctl -w net.core.netdev_max_backlog=300000
sysctl -w net.ipv4.tcp_rmem="10000000 10000000 10000000"
sysctl -w net.ipv4.tcp_wmem="10000000 10000000 10000000"
sysctl -w net.ipv4.tcp_mem="10000000 10000000 10000000"
sysctl -w net.ipv4.udp_rmem="10000000 10000000 10000000"
sysctl -w net.ipv4.udp_wmem="10000000 10000000 10000000"
sysctl -w net.ipv4.udp_mem="10000000 10000000 10000000"
sysctl net.ipv6.conf.all.forwarding=1
sysctl net.ipv6.conf.all.seg6_enabled=1
sysctl net.ipv6.conf.eth0.seg6_enabled=1

ethtool -K eth0 gro off
ethtool -K eth0 gso off
ethtool -K eth0 tx off
ethtool -K eth0 rx off

# ixgbe trick to prevent unnecessary calls to ipv6_find_hdr()
# Improve perfs by ~1Mpps in rx-pause=off mode. No effect (currently)
# in rx-pause=on mode.
ethtool -K eth0 rx-ntuple-filter on

# To enable SRv6 on the raspberry.
# TODO: check which one of the following three makes it work
sudo sysctl net.ipv6.conf.default.seg6_enabled=1
sudo sysctl net.ipv6.conf.lo.seg6_enabled=1
sudo ethtool -K eth0 scatter-gather off

# Also improve perfs in rx-pause=off
ethtool -G eth0 tx 1024
ethtool -C eth0 rx-usecs 30

ip ad add 2042:22::2/64 dev eth0

for i in $(seq 38 45); do echo 7 > /proc/irq/$i/smp_affinity_list; done
