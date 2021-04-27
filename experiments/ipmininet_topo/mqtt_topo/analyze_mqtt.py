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


def read_mqtt_run_json_all(filename):
    with open(filename, "r") as fd:
        data = json.load(fd)
    
    return [i["msg_time_mean"] for i in data["runs"]]


def sort_list(filename):
    nb = filename.split("_")[-1].split(".")[0]
    return int(nb)


def analyze_point_plot_same_K(K=95):
    analyze_point_plot_idx(range((99 - K) * 49, (99 - K + 1) * 49))


def analyze_point_plot_same_D(D=30):
    analyze_point_plot_idx(range(D - 2, (D - 2) + 10 * 49, 49))


def exchanged_bytes():
    data_without = []
    data_rlc = []
    with open("trace_pipe_without.txt", "r") as fd:
        data = fd.readlines()
        for line in data:
            tab = line.split()
            if tab[-3] == "Total":  # Line indicating number of bytes
                data_without.append(int(tab[-1]))
    with open("trace_pipe_rlc.txt", "r") as fd:
        data = fd.readlines()
        for line in data:
            tab = line.split()
            if tab[-3] == "Total":
                data_rlc.append(int(tab[-1]))
    
    # Now separate in subtabs
    data_without_by_k = []
    i = 0
    for k in range(10):
        by_d = []
        for d in range(49):
            by_d.append(data_without[i])
            i += 1
        data_without_by_k.append(by_d)
    
    data_rlc_by_k = []
    i = 0
    for k in range(10):
        by_d = []
        for d in range(49):
            by_d.append(data_rlc[i])
            i += 1
        data_rlc_by_k.append(by_d)
    
    for i in range(10):
        plt.plot(data_without_by_k[i])
        plt.plot(data_rlc_by_k[i])
    #plt.plot(data_without)
    #plt.plot(data_rlc)
    plt.show()


def analyze_point_plot_idx():
    _, _, filenames_without = next(os.walk("results_without_10/"))
    _, _, filenames_with = next(os.walk("results_rlc_3/"))

    sorted_filenames_without = sorted(filenames_without, key=sort_list)
    sorted_filenames_with = sorted(filenames_with, key=sort_list)

    res_without = list()
    res_rlc = list()

    """# I forgot to use JSON format so I need to scrapt like a n00b
    for filename in tqdm(sorted_filenames_without):
        path = os.path.join("results_without_10", filename)
        res_without.append(read_mqtt_run_json_all(path))

    # The same but for RLC
    for filename in tqdm(sorted_filenames_with):
        path = os.path.join("results_rlc_3", filename)
        res_rlc.append(read_mqtt_run_json_all(path))"""
    
    idx = 0
    res_by_k = []
    for k in range(10):
        res_by_d = []
        for d in range(49):
            filename = sorted_filenames_without[idx]
            path = os.path.join("results_without_10", filename)
            res_by_d.append(read_mqtt_run_json(path))
            idx += 1
        res_by_k.append(res_by_d)
    

    idx = 0
    res_by_k_rlc = []
    for k in range(10):
        res_by_d = []
        for d in range(49):
            filename = sorted_filenames_without[idx]
            path = os.path.join("results_rlc_3", filename)
            res_by_d.append(read_mqtt_run_json(path))
            idx += 1
        res_by_k_rlc.append(res_by_d)
    
    for i, elem in enumerate(res_by_k):
        plt.plot(elem, label=i, color="blue")
    for i, elem in enumerate(res_by_k_rlc):
        plt.plot(elem, color="orange")
    plt.legend()
    plt.ylim((20, 60))
    plt.show()



def analyze_latency():
    _, _, filenames_without = next(os.walk("results_without_auto/"))
    _, _, filenames_with = next(os.walk("results_rlc/"))
    # print(filenames_without)

    res_without = list()
    res_rlc = list()

    # I forgot to use JSON format so I need to scrapt like a n00b
    for filename in tqdm(sorted(filenames_without)):
        path = os.path.join("results_without_auto", filename)
        res_without.append(read_mqtt_run_json(path))

    # The same but for RLC
    for filename in tqdm(filenames_with):
        path = os.path.join("results_rlc", filename)
        res_rlc.append(read_mqtt_run_json(path))
    
    print([int(i) for i in res_without if i > 50])

    hist_without, bin_edges_without = np.histogram(res_without, bins=60, range=(20, 58), density=True)
    hist_with, bin_edges_with = np.histogram(res_rlc, bins=60, range=(20, 58), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    cdf_with = np.cumsum(hist_with) * dx

    fig, ax = plt.subplots()
    ax.plot(bin_edges_without[1:], cdf_without, label="TCP", color=(173/255, 205/255, 224/255), linestyle="-")
    ax.plot(bin_edges_with[1:], cdf_with, label="SRv6_FEC_RLC_6_3", color=(43/255, 68/255, 148/255), linestyle="-.")

    ax.grid(axis="y")
    ax.set_axisbelow(True)

    ax.set_ylabel("CDF")
    ax.set_xlabel("Latency (ms)")
    # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

    plt.legend(loc="best")
    plt.savefig("mqtt_latency.svg")
    plt.savefig("mqtt_latency.png")
    plt.show()



if __name__ == "__main__":
    #analyze_latency()
    # analyze_point_plot_same_K(90)
    # analyze_point_plot_same_D(2)
    analyze_point_plot_idx()
    # exchanged_bytes()