import sys
# sys.path.insert(0, "/vagrant/zashas/pyroute2")
sys.path.insert(0, "/vagrant/louis/pyroute2")
import os
import time

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI

from mqtt_topo import MQTTTopoNetwork

net = IPNet(topo=MQTTTopoNetwork())

out = net['rA'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rD'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rE'].pexec('mount -t debugfs none /sys/kernel/debug')
out = net['rC'].pexec('mount -t debugfs none /sys/kernel/debug')

out = net["rA"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rD"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rE"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rC"].pexec("mount -t bpf none /sys/fs/bpf")


""" 
Now the objective is to try to use SubProcess to be able to trace
all packets that are received by a router
"""
#proc = net['r1'].popen('sudo /usr/sbin/biolatency-bpfcc')

try:
    net.start()
    """# Load encoder and decoder programs in other processes
    net["rE"].popen("/vagrant/FEC-SRv6-libbpf/src/encoder fc00::a fc00::9 >> encoder_log.txt")
    net["rC"].popen("/vagrant/FEC-SRv6-libbpf/src/decoder fc00::9 >> decoder_log.txt")

    # Add route linking to End.BPF action
    out = net["rE"].pexec("ip -6 route add fc00::a encap seg6local action End.BPF endpoint fd /sys/fs/bpf/encoder/lwt_seg6local section decode dev rE-eth0")
    print("rE route: ", out)
    out = net["rE"].pexec("ip -6 route add fc00::9 encap seg6local action End.BPF endpoint fd /sys/fs/bpf/decoder/lwt_seg6local section decode dev rC-eth1")
    print("rC route:" ), out

    

    out = net["rD"].popen("/vagrant/FEC-SRv6-libbpf/src/drop")
    #time.sleep(3)
    #out = net["rD"].pexec("ip -6 route add fc00::d encap seg6local action End.BPF endpoint fd /sys/fs/bpf/drop/lwt_seg6local section drop dev rD-eth1")
    for i in range(1000):
        print("ok")
        time.sleep(1)"""
    IPCLI(net)
finally:
    net["rD"].terminate()
    net.stop()