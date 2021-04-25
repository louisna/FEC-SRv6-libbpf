import matplotlib.pyplot as plt
import json
import os
import numpy as np
from tqdm import tqdm


# https://stackabuse.com/reading-and-writing-json-to-a-file-in-python/
def get_median_field(filename: str, field: str) -> float:
    with open(filename) as json_file:
        data = json.load(json_file)


def read_mqtt_run_scrap(filename):
    with open(filename, "r") as fd:
        lines = fd.readlines()
    
    # Offset between two clients
    client_offset = 9

    # Offset for value of interest
    value_offset = 5

    clients_res = []

    for i in range(3):
        line_client_i = lines[value_offset + client_offset * i]
        time_mean_client_i = float(line_client_i.split()[-1])
        clients_res.append(time_mean_client_i)
    

    # Compute the median from all clients
    return np.median(clients_res)


def read_mqtt_run_json(filename):
    with open(filename, "r") as fd:
        data = json.load(fd)
    
    clients_res = [i["msg_time_mean"] for i in data["runs"]]

    # Compute the median for all clients
    return np.median(clients_res)

def analyze_latency():
    _, _, filenames_without = next(os.walk("results_without/"))
    _, _, filenames_with = next(os.walk("results_with/"))
    # print(filenames_without)

    res_without = list()
    res_rlc = list()

    # I forgot to use JSON format so I need to scrapt like a n00b
    for filename in tqdm(sorted(filenames_without)):
        path = os.path.join("results_without", filename)
        res_without.append(read_mqtt_run_json(path))

    # The same but for RLC
    for filename in tqdm(filenames_with):
        path = os.path.join("results_with", filename)
        res_rlc.append(read_mqtt_run_json(path))

    """res_without = [
        22.247950109999998,
        23.288119370000018,
        25.102569915000007,
        24.156464309999997,
        26.630027874999996,
        27.576673965,
        34.050991859999996,
        32.13347691000002,
        37.37875197499998,
        38.281193685000005,
    ]

    res_rlc = [
        22.247950109999998,
        22.769142289999994,
        22.34818648999999,
        22.151033379999976,
        22.881636925000002,
        22.69091150500001,
        23.565572694999993,
        22.37888956000001,
        23.382937155,
        23.764407795,
    ]"""

    hist_without, bin_edges_without = np.histogram(res_without, bins=60, range=(21, 53), density=True)
    hist_with, bin_edges_with = np.histogram(res_rlc, bins=60, range=(21, 53), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    cdf_with = np.cumsum(hist_with) * dx

    fig, ax = plt.subplots()
    ax.plot(bin_edges_without[1:], cdf_without, label="SRv6", color=(173/255, 205/255, 224/255), linestyle="-")
    ax.plot(bin_edges_with[1:], cdf_with, label="SRv6_FEC_RLC_4_2", color=(43/255, 68/255, 148/255), linestyle="-.")

    ax.grid(axis="y")
    ax.set_axisbelow(True)

    ax.set_ylabel("CDF")
    ax.set_xlabel("Latency (ms)")
    # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

    plt.legend(loc="best")
    plt.savefig("mqtt.svg")
    plt.savefig("mqtt.png")
    plt.show()



if __name__ == "__main__":
    analyze_latency()