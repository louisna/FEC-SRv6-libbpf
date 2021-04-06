"""
Sender command:
sudo trafgen --dev eth0 --conf trafgen_configs/srv6.cfg -n 10000000 -b 500000pps --cpus 1

Receiver command:
sudo tcpdump -i eth0 -w test_fec_without_send.pcap -G 120 -W 1
"""

import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.ticker import PercentFormatter

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

encoder_test_name = [
    "Full plugin v0",
    "Full plugin",
    "Without user space packet",
    "Without XOR coding function",
    "Without adding the TLV",
    "Without user space",
    "Without user space and TLV add",
]

def performance_encoder():
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


def performance_encoder_seaborn():
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
    performance_encoder()
    # performance_encoder_seaborn()