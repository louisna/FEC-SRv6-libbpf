from ipmininet.iptopo import IPTopo
from ipmininet.srv6 import enable_srv6
from ipmininet.ipnet import IPNet
import time
import numpy as np
import os

class MQTTTopoNetwork(IPTopo):

    def build(self, *args, **kwargs):
        """
        +-----+     +-----+     +-----+     +-----+     +-----+
        | hA  +-----+ rA  +-----+ rE  +-----+ rD  +-----+ hD  |
        +-----+     +--+--+     +-----+     +--+--+     +-----+
        """ 
        rA, rE, rD = self.addRouters('rA', 'rE', 'rD', use_v4=False, use_v6=True)

        # MQTT host/server
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

        l = self.addLink(rE, rD, delay="10ms")
        l[rE].addParams(ip="2042:de::e/64")
        l[rD].addParams(ip="2042:de::d/64")

        super().build(*args, **kwargs)
    
    def post_build(self, net):
        for n in net.hosts + net.routers:
            enable_srv6(n)
        
        super().post_build(net)


net = IPNet(topo=MQTTTopoNetwork())

out = net['rA'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rD'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rE'].pexec('mount -t debugfs none /sys/kernel/debug')

out = net["rA"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rD"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rE"].pexec("mount -t bpf none /sys/fs/bpf")


try:
    net.start()

    # Start Mosquitto forever
    net["hD"].popen("mosquitto")

    # Add encapsulation forever
    net["rA"].pexec("ip -6 route add 2042:dd::1/64 encap seg6 mode inline segs fc00::a,fc00::9 dev rA-eth0")
    
    i = 0
    # Start loop for every sample of the Markov model
    output_file = f"testons/mqtt_run_{i}.json"  # SIGCOMM: put here the output directory
    with open(output_file, "a+") as fd:
        fd.write("[")
    for k in [99, 98, 97, 96, 95, 94, 93, 92, 91, 90]:
        for d in np.arange(0, 51, 2):
            with open(output_file, "a+") as fd:
                fd.write("[")
                for run in range(3):
                    print(f"k={k}, d={d}, run={run}")
                    # Start plugin
                    encoder = net["rE"].popen("../../../src/encoder -a -i rE-eth0")  # Add -w and -s accordingly
                    decoder = net["rD"].popen("../../../src/decoder -a -i rD-eth0")
                
                    # Start dropper
                    # SIGCOMM: adapt to find the file
                    dropper = net["rD"].pexec(f"python3 /vagrant/ebpf_dropper/attach_markov.py --ips 204200dd00000000,0000000000000001,fc00000000000000,0000000000000009 --attach rD-eth1 --attach-ingress -k {k} -d {d}")
                    print(dropper)

                    # Wait for the plugins and dropper to start
                    time.sleep(2)

                    # Start tcpdump to listen to the packets
                    tcpdump = net["rD"].popen("tcpdump -i rD-eth1 -w /vagrant/cap.pcap")  # SIGCOMM: put here the output file of tcpdump

                    # Start benchmark in main thread
                    out = net["hA"].pexec(f"/home/vagrant/go/bin/mqtt-benchmark --broker tcp://[2042:dd::1]:1883 --clients 10 --count 100 --format json >> {output_file}")
                    fd.write(out[0])
                    
                    # Stop all running process before next iteration
                    encoder.terminate()
                    decoder.terminate()
                    tcpdump.terminate()
                    net["rD"].pexec("python3 attach_markov.py --ips 204200dd00000000,0000000000000001,fc00000000000000,0000000000000009 --attach rD-eth1 --attach-ingress --clean")
                    if run < 2: fd.write(",")
                    i += 1
                fd.write("]")
                if i < 259: fd.write(",")
        with open(output_file, "a+") as fd:
            fd.write("]")
    
finally:
    net["rD"].terminate()
    net.stop()