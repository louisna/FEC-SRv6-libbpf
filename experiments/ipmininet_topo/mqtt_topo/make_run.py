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

out = net["rA"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rD"].pexec("mount -t bpf none /sys/fs/bpf")
out = net["rE"].pexec("mount -t bpf none /sys/fs/bpf")


""" 
Now the objective is to try to use SubProcess to be able to trace
all packets that are received by a router
"""
#proc = net['r1'].popen('sudo /usr/sbin/biolatency-bpfcc')

try:
    net.start()
    IPCLI(net)
finally:
    net["rD"].terminate()
    net.stop()