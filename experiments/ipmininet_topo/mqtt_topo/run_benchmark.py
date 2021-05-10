import os
import sys
import signal
sys.path.insert(0, "/vagrant/scapy")

from scapy.all import IPv6, IPv6ExtHdrSegmentRouting, UDP, Raw
from scapy.all import send
import time


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


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
print('Press Ctrl+C')

#output_dir_template = lambda: f"/Volumes/LOUIS/thesis/results_without/mqtt_res_run_{i}.json"
output_dir_template = lambda: f"mqtt_topo/results_without_2500/mqtt_res_run_10_-{i+1}.json"
mqtt_bench_template = f"/home/vagrant/go/bin/mqtt-benchmark --broker tcp://[2042:dd::1]:1883 --clients 10 --count 500 --format json"

scapy_args = Crafting(verbose=False, source="2042:aa::1", destination="fc00::9", port=3333)

for i in range(1):
    output_dir = output_dir_template()
    f"echo [ >> {output_dir}"
    command = f"{mqtt_bench_template} >> {output_dir}"
    for i in range(3):  # repeat each experiment 3 times
        os.system(command)
        f"echo , >> {output_dir}"
    f"echo ] >> {output_dir}"

    # Notify the dropper that we can update the parameters for the next state
    pkt = craft_srv6_packet(scapy_args, "zzzzzzzzzzz")
    send(pkt)
    print("Sent update packet !")
    time.sleep(0.1)