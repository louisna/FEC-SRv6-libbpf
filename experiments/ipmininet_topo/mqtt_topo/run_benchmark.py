import os
import sys
import signal
sys.path.insert(0, "/vagrant/scapy")

from scapy.all import IPv6, IPv6ExtHdrSegmentRouting, UDP, Raw
from scapy.all import send
import time
import argparse


class Crafting:
    def __init__(self, verbose, source, destination, port):
        self.verbose = verbose
        self.source = source
        self.destination = destination
        self.port = port

def craft_srv6_packet(args, payload) -> IPv6:
    pkt = IPv6()
    pkt.src = args.source

    if args.destination:
        pkt.dst = args.destination
    else:
        pkt.dst = args.segments[-1]

        # Segment Routing Header
        srh = IPv6ExtHdrSegmentRouting()
        srh.addresses = args.segments
        srh.lastentry = len(srh.addresses) - 1
        pkt = pkt / srh

    # Transport layer
    transport = UDP(sport=123, dport=args.port)
    pkt = pkt / transport

    # Payload
    pkt = pkt / Raw(payload)
    
    if args.verbose:
        pkt.show()

    return pkt


def update_idx_delay():
    with open("delay/helper.txt", "r") as fd:
        i = int(fd.read())
    with open("delay/helper.txt", "w") as fd:
        fd.write(str(i+5))
        return i


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
print('Press Ctrl+C')

parser = argparse.ArgumentParser()
parser.add_argument("--fec", help="Test using FEC", action="store_true")
args = parser.parse_args()

#output_dir_template = lambda: f"/Volumes/LOUIS/thesis/results_without/mqtt_res_run_{i}.json"
# output_dir_template = lambda: f"mqtt_topo/results_without_2500/mqtt_res_run_10_{idx}.json"
output_dir_template = lambda: f"results_26_05/without/mqtt_res_run_{i}.json"
mqtt_bench_template = f"/home/vagrant/go/bin/mqtt-benchmark --broker tcp://[2042:dd::1]:1883 --clients 10 --count 100 --format json"

update_address = "fc00::9" if args.fec else "2042:dd::1"
scapy_args = Crafting(verbose=False, source="2042:aa::1", destination=update_address, port=3333)
scapy_args_run = Crafting(verbose=False, source="2042:aa::1", destination=update_address, port=3334)

for i in range(1):
    output_dir = output_dir_template()
    #os.system(f"echo [ >> {output_dir}")
    command = f"{mqtt_bench_template} "#>> {output_dir}"
    for j in range(1):  # repeat each experiment 3 times
        os.system(command)
        if j < 2:
            #os.system(f"echo , >> {output_dir}")
            pkt = craft_srv6_packet(scapy_args_run, "yyyyyyyyyyyy")
            send(pkt)
            pass
    #os.system(f"echo ] >> {output_dir}")

    # Notify the dropper that we can update the parameters for the next state
    pkt = craft_srv6_packet(scapy_args, "zzzzzzzzzzz")
    #send(pkt)
    print("Sent update packet !")
    time.sleep(0.1)