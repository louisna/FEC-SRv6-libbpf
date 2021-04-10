import sys
sys.path.insert(0, "/vagrant/louis/pyroute2")
sys.path.insert(0, "/vagrant/scapy")

from scapy.all import IPv6, IPv6ExtHdrSegmentRouting, UDP, Raw
from scapy.all import send

import time
import math
import argparse

class WrongPacketSize(Exception):
    pass

def craft_srv6_packet(args, payload) -> IPv6:
    pkt = IPv6()
    pkt.src = args.source
    pkt.dst = args.segments[-1]

    # Segment Routing Header
    srh = IPv6ExtHdrSegmentRouting()
    srh.addresses = args.segments
    srh.lastentry = len(srh.addresses) - 1
    pkt = pkt / srh

    # Transport layer
    transport = UDP(sport=123, dport=456)
    pkt = pkt / transport

    # Payload
    pkt = pkt / Raw(payload)
    
    if args.verbose:
        pkt.show()

    return pkt


def send_packets_default(args) -> None:

    #payload_template = lambda: f"FFFEEE, Scapy number {i}! \
    #    Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
    #    Donec lacinia nulla a elit euismod porta quis quis dolor."
    payload_template = lambda: f"{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}"

    for i in range(int(args.number_packets)):
        pkt = craft_srv6_packet(args, payload_template())
        send(pkt)
        time.sleep(args.sleep_time)

        if args.verbose:
            print(f"Sending packet #{i}")
    
    if args.verbose:
        print(f"Sent {args.number_packets} packet!")


def send_packets_from_file(args) -> None:
    filename, packet_size = args.file
    packet_size = int(packet_size)
    if packet_size < 1:
        raise WrongPacketSize()
    with open(filename, "r") as fd:
        all_payload = fd.read()
        nb_packets = math.ceil(len(all_payload) / packet_size)
        for i in range(nb_packets):
            packet_payload = all_payload[i * packet_size: (i+1) * packet_size]
            pkt = craft_srv6_packet(args, packet_payload)
            send(pkt)
            time.sleep(args.sleep_time)

            if args.verbose:
                print(f"Sending packet #{i}")
    
        if args.verbose:
            print(f"Sent {nb_packets} packets !")


def main():
    parser = argparse.ArgumentParser(description="Send Scapy packets for FEC SRv6 plugin")
    parser.add_argument("-n", "--number_packets", help="Number of packets to send", type=int, default=10)
    parser.add_argument("-s", "--segments", help="List of segments of the packet", nargs="+", default=["2042:22::2", "fc00::9", "fc00::d", "fc00::a"])
    parser.add_argument("-c", "--source", help="Source of the SRv6 packet", default="fc00::2")
    parser.add_argument("-t", "--sleep_time", help="Time in seconds between two consecutive packets", type=float, default=0.001)
    parser.add_argument("-f", "--file", help="Input file to find the payload. First=filename, second=packet size", nargs="+", default=None)
    parser.add_argument("-v", "--verbose", help="Print debug messages", action="store_true")
    args = parser.parse_args()

    print(args, file=sys.stderr)

    if args.file:
        send_packets_from_file(args)
    else:
        send_packets_default(args)


if __name__ == "__main__":
    main()