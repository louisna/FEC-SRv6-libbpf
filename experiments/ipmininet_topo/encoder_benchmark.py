from ipmininet.iptopo import IPTopo
from ipmininet.router.config import RouterConfig
from ipmininet.router.config.ripng import RIPng
from ipmininet.srv6 import SRv6EndBPFFunction, enable_srv6
from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI


class EncoderBenchmark(IPTopo):

    def build(self, *args, **kwargs):
        """
        +-----+     +-----+     +-----+
        | h1  +-----+  r  +-----+ h2  +
        +-----+     +-----+     +-----+
        """
        r = self.addRouter('r', use_v4=False, use_v6=True, lo_addresses=["2042:ff::/64"])

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        l = self.addLink(r, h1)
        l[r].addParams(ip="2042:11::1/64")
        l[h1].addParams(ip="2042:11::2/64")

        l = self.addLink(r, h2)
        l[r].addParams(ip="2042:22::1/64")
        l[h2].addParams(ip="2042:22::2/64")

        super().build(*args, **kwargs)
    
    def post_build(self, net):
        for n in net.hosts + net.routers:
            enable_srv6(n)

        super().post_build(net)


net = IPNet(topo=EncoderBenchmark())

out = net['r'].pexec("mount -t debugfs none /sys/kernel/debug")
print(out)
out = net['r'].pexec("mount -t bpf none /sys/fs/bpf")
print(out)

try:
    net.start()
    IPCLI(net)
finally:
    net.stop()