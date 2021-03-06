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


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

parser = argparse.ArgumentParser()
parser.add_argument("--output", help="Output directory for the results", default=None)
parser.add_argument("--delay", help="Delay of the link rE-rD [ms]", type=int, default=10)
parser.add_argument("--udp", help="Use UDP instead of TCP", action="store_true")
parser.add_argument("--tcp-quality", help="Quality measurement TCP [bits]", type=int, default=0)
parser.add_argument("--fec", help="Test using FEC", action="store_true")
parser.add_argument("-t", help="Time of a test [s]", type=int, default=45)
parser.add_argument("-b", help="Bit rate in bps", type=int, default=1000000)
args = parser.parse_args()

protection = "rlc" if args.fec else "without"
transport = "udp" if args.udp else "tcp"
update_destination = "fc00::9" if args.fec else "2042:dd::1"

signal.signal(signal.SIGINT, signal_handler)
print('Press Ctrl+C')
if args.tcp_quality == 0:
    transport_cmd = "--udp -l 280" if args.udp else "-M 280"
    output_dir_template = f" >> {args.output}/run_udp_global.json"
    bench_template = f"iperf3 -c 2042:dd::1 -t {args.t} {transport_cmd} --json"
    # bench_template = f"iperf3 -c 2042:dd::1 --bytes 10000000 {transport_cmd} --json"
    print(bench_template)
    scapy_args = Crafting(verbose=False, source="2042:aa::1", destination=update_destination, port=3333)
    scapy_args_run = Crafting(verbose=False, source="2042:aa::1", destination=update_destination, port=3334)

    output_dir = "" if args.output is None else output_dir_template
    if len(output_dir) > 0: os.system(f"echo [ {output_dir}")
    for i in range(104):
        print(i)
        if len(output_dir) > 0: os.system(f"echo [ {output_dir}")
        command = f"{bench_template} {output_dir}"
        for i in range(3):
            os.system(command)
            if i < 2:
                if len(output_dir) > 0: os.system(f"echo , {output_dir}")
                pkt = craft_srv6_packet(scapy_args_run, "yyyyyyyyyyyy")
                send(pkt)
        if len(output_dir) > 0: os.system(f"echo ] {output_dir}")
        if i < 259: os.system(f"echo , {output_dir}")

        # Notify the dropper that we can update the parameters for the next state
        pkt = craft_srv6_packet(scapy_args, "zzzzzzzzzzz")
        send(pkt)
        print("Sent update packet !")
        time.sleep(1)
    os.system(f"echo ] {output_dir}")
else:
    output_dir_template = lambda: f"{args.output}.json"
    bench_template = f"iperf3 --client 2042:dd::1 --bytes {args.tcp_quality} -M 280"
    output_dir = "" if args.output is None else output_dir_template()
    scapy_args = Crafting(verbose=False, source="2042:aa::1", destination=update_destination, port=3333)
    #os.system(f"echo [ >> {output_dir}")
    for i in range(260):
        print(i)
        # if len(output_dir) > 0: os.system(f"echo [ {output_dir}")
        command = f"{bench_template} "#>> {output_dir}"
        for j in range(1):
            os.system(command)
            if j < 2:
                #if len(output_dir) > 0: os.system(f"echo , {output_dir}")
                pass
        #if i < 259: os.system(f"echo , >> {output_dir}")

        pkt = craft_srv6_packet(scapy_args, "zzzzzzzzzzz")
        send(pkt)
        print("Sent update packet !")
        time.sleep(0.1)
    #os.system(f"echo ] >> {output_dir}")