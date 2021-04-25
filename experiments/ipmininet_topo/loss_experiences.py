import os, sys
import itertools
import time

from mac_to_hex import convert
from itertools import groupby, product
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
#from scapy.all import send
#from scapy_send_packets import craft_srv6_packet

class Crafting:
    def __init__(self, verbose, source, segments):
        self.verbose = verbose
        self.source = source
        self.segments = segments

def send_traffic():
    nb_experiments = 3
    vals = ['a', 'b', 'c']

    args = Crafting(False, "2042:aa::2", ["2042:22::2", "fc00::9", "fc00::d", "fc00::a"])
    # args = Crafting(False, "2042:aa::2", ["2042:22::2", "fc00::d"])

    for i in range(nb_experiments):
        pkt = craft_srv6_packet(args, vals[i])
        send(pkt, count=1000)
        time.sleep(0.001)


def repeat_for_each_param():
    info_packet_args = Crafting(False, "2042:aa::2", ["2042:22::2"])
    d_range = range(2, 51)
    k_range = range(98, 89, -1)
    i = 0
    for k, d in product(k_range, d_range):
        print(f"For values k={k} d={d}")
        payload = f"--- Test values: k={k} d={d} ---\n"
        if i != 0:
            payload = "\n" + payload        
        info_packet = craft_srv6_packet(info_packet_args, payload)
        send(info_packet)
        time.sleep(0.001)
        send_traffic()
        i += 1
        time.sleep(2)


def read_result_and_compute(filename):
    vals = ['a', 'b', 'c']
    res = []
    with open(filename, "r") as fd:
        # Should have 3 different values
        txt = str(fd.read())
        for line in txt.split("\n"):
            if line[0] == "-":
                continue
            captured = [line.count(i) for i in line]
            res.append(np.median(captured)/1000)
    return res


def analyze_traffic():
    vals = ['a', 'b', 'c']
    res_without = read_result_and_compute("lossy_res_without.txt")
    print(res_without)
    res_with = read_result_and_compute("lossy_res_with.txt")
    res_xor = read_result_and_compute("lossy_res_xor.txt")
    hist_without, bin_edges_without = np.histogram(res_without, bins=40, range=(0.9, 1), density=True)
    hist_with, bin_edges_with = np.histogram(res_with, bins=40, range=(0.9, 1), density=True)
    hist_xor, bin_edges_xor = np.histogram(res_xor, bins=40, range=(0.9, 1), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    cdf_with = np.cumsum(hist_with) * dx
    cdf_xor = np.cumsum(hist_xor) * dx

    fig, ax = plt.subplots()
    ax.plot(bin_edges_without[1:], cdf_without, label="SRv6", color=(173/255, 205/255, 224/255), linestyle="-")
    ax.plot(bin_edges_with[1:], cdf_with, label="SRv6_FEC_RLC_6_3", color=(43/255, 68/255, 148/255), linestyle="-.")
    ax.plot(bin_edges_with[1:], cdf_xor, label="SRv6_FEC_XOR_3", color=(254/255, 47/255, 9/255), linestyle="--")

    ax.grid(axis="y")
    ax.set_axisbelow(True)

    ax.set_ylabel("CDF")
    ax.set_xlabel("Packets received (%)")
    plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

    plt.legend(loc="best")
    plt.savefig("received_data.svg")
    plt.savefig("received_data.png")
    plt.show()

if __name__ == "__main__":
    if sys.argv[1] == "0":
        send_traffic()
    elif sys.argv[1] == "1":
        analyze_traffic()
    elif sys.argv[1] == "2":
        repeat_for_each_param()