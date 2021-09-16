import subprocess
import sys
sys.path.insert(0, "/vagrant/louis/pyroute2")
import os
import time

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI

from ipmininet.iptopo import IPTopo
from ipmininet.router.config import RouterConfig
from ipmininet.router.config.ripng import RIPng
from ipmininet.srv6 import SRv6EndBPFFunction, enable_srv6

class CompareTcpUdpPlugin(IPTopo):

    def build(self, *args, **kwargs):
        """
        +-----+     +-----+     +-----+     +-----+     +-----+
        | hA  +-----+ rA  +-----+ rE  +-----+ rD  +-----+ hD  |
        +-----+     +--+--+     +-----+     +--+--+     +-----+
        """ 
        rA, rE, rD = self.addRouters('rA', 'rE', 'rD', use_v4=False, use_v6=True)

        # Sender and receiver
        hA = self.addHost('hA')
        hD = self.addHost('hD')

        # Host links
        self.addLinks((hA, rA), (hD, rD))
        self.addSubnet(nodes=[hA, rA], subnets=["2042:aa::/64"])
        self.addSubnet(nodes=[hD, rD], subnets=["2042:dd::/64"])

        # Links between routers
        l = self.addLink(rA, rE)
        l[rA].addParams(ip="2042:ae::a/64")
        l[rE].addParams(ip="2042:ae::e/64")

        l = self.addLink(rE, rD, delay="10ms", bw=15)
        l[rE].addParams(ip="2042:de::e/64")
        l[rD].addParams(ip="2042:de::d/64")

        super().build(*args, **kwargs)
    
    def post_build(self, net):
        for n in net.hosts + net.routers:
            enable_srv6(n)
        
        super().post_build(net)


# Launch topo
net = IPNet(topo=CompareTcpUdpPlugin())

out = net['rA'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rD'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rE'].pexec('mount -t debugfs none /sys/kernel/debug')

out = net["rA"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rD"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rE"].pexec("mount -t bpf none /sys/fs/bpf")

# Limit MSS
out = net["hA"].pexec("ethtool -K hA-eth0 tso off")

out = net["rA"].pexec("ethtool -K rA-eth0 tso off")
out = net["rA"].pexec("ethtool -K rA-eth1 tso off")

out = net["rE"].pexec("ethtool -K rE-eth0 tso off")
out = net["rE"].pexec("ethtool -K rE-eth1 tso off")

out = net["rD"].pexec("ethtool -K rD-eth0 tso off")
out = net["rD"].pexec("ethtool -K rD-eth1 tso off")

out = net["hD"].pexec("ethtool -K hD-eth0 tso off")

# Not save TCP metrics
out = net["hA"].pexec("sysctl net.ipv4.tcp_no_metrics_save=1")
out = net["hD"].pexec("sysctl net.ipv4.tcp_no_metrics_save=1")

#MTU = 450
#for intf in [intf for h in net.routers for intf in h.intfNames()]:
#    subprocess.call(['ifconfig', intf, 'mtu', str(MTU)])

try:
    net.start()
    IPCLI(net)
finally:
    net.stop()