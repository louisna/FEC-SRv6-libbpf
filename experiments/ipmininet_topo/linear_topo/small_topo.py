"""This file contains a simple example of topology connected with OSPF"""

from ipmininet.iptopo import IPTopo
from ipmininet.router.config import RouterConfig
from ipmininet.router.config.ripng import RIPng
from ipmininet.srv6 import SRv6EndBPFFunction, enable_srv6


class SmallTopoNetwork(IPTopo):

    def build(self, *args, **kwargs):
        """
        +-----+     +-----+     +-----+     +-----+     +-----+     +-----+     +-----+
        | hA  +-----+ rA  +-----+ rE  +-----+ r1  +-----+ rC  +-----+ r2  +-----+  h2 |
        +-----+     +-----+     +-----+     +-----+     +-----+     +-----+     +-----+
        """
        r1, r2, rA, rE, rC = self.addRouters('r1', 'r2', 'rA', 'rE', 'rC',
                                use_v4=False, use_v6=True)

        hA = self.addHost('hA')
        h2 = self.addHost('h2')

        self.addLinks((hA, rA), (h2, r2))

        lr1rE = self.addLink(r1, rE)
        lr1rE[r1].addParams(ip="2042:1e::1/64")
        lr1rE[rE].addParams(ip="2042:1e::e/64")

        lrArE = self.addLink(rA, rE, delay="50ms")
        lrArE[rE].addParams(ip="2042:ae::e/64")
        lrArE[rA].addParams(ip="2042:ae::a/64")

        lr1rC = self.addLink(r1, rC)
        lr1rC[r1].addParams(ip="2042:1c::1/64")
        lr1rC[rC].addParams(ip="2042:1c::c/64")

        lrCr2 = self.addLink(r2, rC)
        lrCr2[rC].addParams(ip="2042:2c::c/64")
        lrCr2[r2].addParams(ip="2042:2c::2/64")

        self.addSubnet(nodes=[rA, hA], subnets=["2042:aa::/64"])
        self.addSubnet(nodes=[r2, h2], subnets=["2042:22::/64"])

        super().build(*args, **kwargs)
    
    def post_build(self, net):
        for n in net.hosts + net.routers:
            enable_srv6(n)
        #SRv6EndBPFFunction(net=net, node="r1", to="2042:1a::1",
        #                    prog_path="senderClean.o",
        #                    prog_name="encode")
        

        super().post_build(net)
