"""
Sender command:
sudo trafgen --dev eth0 --conf trafgen_configs/srv6.cfg -n 10000000 -b 500000pps --cpus 1

Receiver command:
sudo tcpdump -i eth0 -w test_fec_without_send.pcap -G 120 -W 1
"""

import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.ticker import PercentFormatter
import numpy as np

encoder_res = [
    3074125,  # Normal
    646428,   # Initial full plugin
    1178506,  # Plugin with userspace and send second time
    # 1668552,  # Plugin with userspace first time
    1188425,  # Plugin with userspace second time
    # 1338214,  # Plugin with userspace and send first time
    1289609,  # Plugin with userspace without XOR
    1752408,  # Plugin with user space without add tlv
    2699241,  # Plugin without userspace
    2681295,  # Plugin without userspace witout add tlv without
]

encode_names = [
    "RLC",
    "RLC without US",
    "XOR",
    "XOR without US"
]

encode_64 = [
    3218608,  # Normal
    2265321,  # RLC
    3105847,  # RLC without user space
    2054748,  # XOR otl
    3059001,  # XOR without user space
]

encode_200 = [
    2848759,  # Normal
    2608332,  # RLC
    2746248,  # RLC without user space
    2773159,  # XOR
    2801332,  # XOR without user space
]

encode_1 = [
    2799868,  # Normal
    2639912,  # RLC
    2748049,  # RLC without user space
    2766617,  # XOR
    2783880,  # XOR without user space 
]

encoder_test_name = [
    "Full plugin v0",
    "Full plugin",
    "Without user space packet",
    "Without XOR coding function",
    "Without adding the TLV",
    "Without user space",
    "Without user space and TLV add",
]

"""
Form is the following:
[0]: nb packets without FEC
[1]: nb source symbols / payload
[2]: nb repair symbols
"""
without_loss = [
    (100000, 100000, 0),  # On h2
    (100000, 100000, 24532),  # On r2
]
loss_15 = [
    (85016, )
]

def performance_encoder(encoder_res, encoder_test_name):
    percentages = [(i / encoder_res[0]) for i in encoder_res[1:]]

    fig, ax = plt.subplots()
    ax.bar(encoder_test_name, percentages, color="royalblue")
    fig.autofmt_xdate()
    ax.grid(axis="y")
    ax.set_axisbelow(True)
    plt.ylabel("Captured packets per second, normalized")
    plt.gca().yaxis.set_major_formatter(PercentFormatter(1))
    plt.title("The baseline is a simple SRv6 packet with no action")
    plt.tight_layout()
    plt.savefig("encoder_performance.svg")
    plt.show()


def encoder_bench_side_by_side(encoder_res):
    percentages = [(i / encoder_res[0]) for i in encoder_res[1:]]

    fig, ax = plt.subplots()
    with_us = [percentages[0], percentages[2]]
    without_us = [percentages[1], percentages[3]]

    ind = np.arange(2)
    width = 0.25
    ax.bar(ind, with_us, width, label="Full plugin", color=(173/255, 205/255, 224/255))
    ax.bar(ind + width, without_us, width, label="Without US", color=(43/255, 68/255, 148/255))

    ax.grid(axis="y")
    ax.set_axisbelow(True)
    plt.ylabel("Captured packets per second, normalized")
    plt.gca().yaxis.set_major_formatter(PercentFormatter(1))

    plt.title("The baseline is a simple SRv6 packet with no action")

    plt.xticks(ind + width / 2, ("RLC", "XOR"))

    plt.legend(loc="best")
    plt.savefig("encoder_benchmark.svg")
    plt.show()


def performance_encoder_seaborn(encoder_res):
    percentages = [(i / encoder_res[0]) * 100 for i in encoder_res[1:]]
    # sns.set_theme(style="whitegrid")
    ax = sns.barplot(x=encoder_test_name, y=percentages)
    # fig.autofmt_xdate()
    plt.savefig("encoder_performance.png")
    plt.ylabel("Percentage")
    plt.title("Comparison of encoder performance w/ respect to a \nsimple SRv6 packet with no action")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    # performance_encoder(encode_64, encode_names)
    # performance_encoder_seaborn()
    encoder_bench_side_by_side(encode_64)