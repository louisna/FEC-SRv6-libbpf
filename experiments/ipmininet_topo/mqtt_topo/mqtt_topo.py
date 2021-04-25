from ipmininet.iptopo import IPTopo
from ipmininet.router.config import RouterConfig
from ipmininet.router.config.ripng import RIPng
from ipmininet.srv6 import SRv6EndBPFFunction, enable_srv6

class MQTTTopoNetwork(IPTopo):

    def build(self, *args, **kwargs):
        """
        +-----+     +-----+     +-----+     +-----+     +-----+     +-----+
        | hA  +-----+ rA  +-----+ rE  +-----+ rD  +-----+ rC  +-----+ hC  |
        +-----+     +--+--+     +-----+     +-----+     +--+--+     +-----+
                       |                                   |
                    +--+--+                             +--+--+
                    | h1  |                             | h2  |
                    +-----+                             +-----+
        """ 
        rA, rE, rD, rC = self.addRouters('rA', 'rE', 'rD', 'rC', use_v4=False, use_v6=True)

        # MQTT host/server
        hA = self.addHost('hA')
        hC = self.addHost('hC')

        # UDP traffic hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        # Host links
        self.addLinks((hA, rA), (hC, rC), (h1, rA), (h2, rC))
        self.addSubnet(nodes=[hA, rA], subnets=["2042:aa::/64"])
        self.addSubnet(nodes=[h1, rA], subnets=["2042:a1::/64"])
        self.addSubnet(nodes=[hC, rC], subnets=["2042:cc::/64"])
        self.addSubnet(nodes=[h2, rC], subnets=["2042:c2::/64"])

        # Links between routers
        l = self.addLink(rA, rE)
        l[rA].addParams(ip="2042:ae::a/64")
        l[rE].addParams(ip="2042:ae::e/64")

        l = self.addLink(rE, rD, delay="10ms")
        l[rE].addParams(ip="2042:de::e/64")
        l[rD].addParams(ip="2042:de::d/64")

        l = self.addLink(rD, rC)
        l[rD].addParams(ip="2042:cd::c/64")
        l[rC].addParams(ip="2042:cd::d/64")

        super().build(*args, **kwargs)
    
    def post_build(self, net):
        for n in net.hosts + net.routers:
            enable_srv6(n)
        
        super().post_build(net)
