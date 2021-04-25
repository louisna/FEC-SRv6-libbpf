import sys
# sys.path.insert(0, "/vagrant/zashas/pyroute2")
sys.path.insert(0, "/vagrant/louis/pyroute2")
import os

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI

from linear_topo.small_topo import SmallTopoNetwork

net = IPNet(topo=SmallTopoNetwork())

""" 
The following three lines produce the output:
<class 'tuple'>
('11\n', '', 0)
"""
out = net['r1'].pexec('python scripts/simple_sum.py')
out = net['r1'].pexec('mount -t debugfs none /sys/kernel/debug')  # This command is magic
out = net['rA'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['r2'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rE'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rC'].pexec('mount -t debugfs none /sys/kernel/debug')
print(type(out))
print(out)

out = net["r1"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rA"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["r2"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rE"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rC"].pexec("mount -t bpf none /sys/fs/bpf")
print("Output of mount:", out)

# out = net["rA"].pexec("ip -6 route add 2042:1a::1 encap bpf out obj /vagrant/coding-network/run_clean_tlv/src/bpf/senderClean.o sec encode headroom 112 dev rA-eth1")
#out = net["r1"].pexec("ip -6 route add 2042:1a::3 encap seg6local action End.BPF endpoint object /vagrant/coding-network/run_clean_tlv/src/bpf/senderClean.o section encode metric 1 dev r1-eth0")
#out = net["rA"].pexec("ip -6 route add 2042:1a::1 encap seg6local action End.BPF endpoint object /vagrant/coding-network/run_clean_tlv/src/bpf/senderClean.o section encode metric 1 dev rA-eth1")
#out = net["r2"].pexec("ip -6 route add 2042:1a::1 encap seg6local action End.BPF endpoint object /vagrant/coding-network/run_clean_tlv/src/bpf/senderClean.o section encode metric 1 dev r2-eth0")
print("Rip le out", out[0])
print(out[1])
print(out[2])

""" 
Now the objective is to try to use SubProcess to be able to trace
all packets that are received by a router
"""
#proc = net['r1'].popen('sudo /usr/sbin/biolatency-bpfcc')

try:
    net.start()
    IPCLI(net)
finally:
    net.stop()