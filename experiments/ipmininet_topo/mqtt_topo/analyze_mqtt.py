import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import json
import os
import numpy as np
from tqdm import tqdm
import matplotlib.gridspec as gridspec


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
    # print(clients_res)
    return np.median(clients_res)


def scrap_mqtt_json_multiple_run(filename):
    with open(filename, "r") as fd:
        data = fd.readlines()
    
    res_by_run = []

    total = 0
    for i, line in enumerate(data):
        if line.split()[0] == '"totals":':
            interest = data[i + 8].split()[-1][:-1]  # Avoid the ','
            res_by_run.append(float(interest))
            total += 1
            if total == 3: break
    
    print(res_by_run)
    
    return np.median(res_by_run)


def rewrite_json(filename):
    with open(filename, "r+") as fd:
        content = fd.read()
        fd.seek(0, 0)
        fd.write("[\n" + content + "]")


def read_mqtt_run_json_all(filename):
    with open(filename, "r") as fd:
        data = json.load(fd)
    
    return [i["msg_time_mean"] for i in data["runs"]]


def sort_list_by_idx(filename):
    nb = filename.split("_")[-1].split(".")[0]
    return int(nb)


def sort_list_by_double_idx(filename):
    delay = filename.split("_")[-2]
    idx = filename.split("_")[-1].split(".")[0]
    return int(delay) * 100 + int(idx)

def loss_varying_delay(MARKOV=True):
    if MARKOV:
        _, _, filenames_without = next(os.walk("results_without_delay/"))
        _, _, filenames_with = next(os.walk("results_rlc_delay/"))
        nb_exp = 19
        idxs_to_plot = np.arange(99, 89.5, -0.5)
    else:
        _, _, filenames_without = next(os.walk("results_without_uniform/"))
        _, _, filenames_with = next(os.walk("results_rlc_uniform/"))
        nb_exp = 31
        idxs_to_plot = np.arange(0, 15.1, 0.5)

    sorted_filenames_without = sorted(filenames_without, key=sort_list_by_double_idx)
    sorted_filenames_rlc = sorted(filenames_with, key=sort_list_by_double_idx)
    res_by_delay_without = []
    res_by_delay_rlc = []
    idx = 0
    for delay in [5, 10, 15]:
        res_by_u_without = []
        res_by_u_rlc = []
        for u in range(nb_exp):
            filename = sorted_filenames_without[idx]
            if MARKOV:
                path = os.path.join("results_without_delay", filename)
            else:
                path = os.path.join("results_without_uniform", filename)
            res_by_u_without.append(read_mqtt_run_json(path))
            
            filename = sorted_filenames_rlc[idx]
            if MARKOV:
                path = os.path.join("results_rlc_delay", filename)
            else:
                path = os.path.join("results_rlc_uniform", filename)
            res_by_u_rlc.append(read_mqtt_run_json(path))

            idx += 1
        res_by_delay_without.append(res_by_u_without)
        res_by_delay_rlc.append(res_by_u_rlc)
    
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)
    linestyles = ["-", "--", ":"]
    colors_without = ["lightcoral", "red", "firebrick", "darkred"]
    colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]

    p_without = []
    p_rlc = []
    
    for idx, res_delay in enumerate(res_by_delay_without):
        p, = ax.plot(idxs_to_plot, res_delay, marker=".", linestyle=linestyles[idx], color=colors_without[idx+1])
        p_without.append(p)
    
    for idx, res_delay in enumerate(res_by_delay_rlc):
        p, = ax.plot(idxs_to_plot, res_delay, marker=".", linestyle=linestyles[idx], color=colors_rlc[idx+1])
        p_rlc.append(p)
    
    # Dummy plot
    p5, = plt.plot([0], marker='None',
           linestyle='None', label='dummy-tophead')

    if MARKOV:
        ax.set_xlabel("Value of the 'k' parameter of the Uniform loss model")
    else:
        ax.set_xlabel("Value of the 'u' parameter of the Uniform loss model")
    ax.set_ylabel("Mean latency [ms]")
    lat_str = [str(i) + "ms" for i in [5, 10, 15]]
    leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
              ["TCP"] + lat_str + ["RLC"] + lat_str,
              loc=2, ncol=2) # Two columns, vertical group labels
    if MARKOV:
        plt.xlim((99.5, 89.5))
        plt.ylim((10, 60))
        plt.xticks(np.arange(90, 100, 1))
        plt.savefig("exp_mqtt_varying_delay_markov.svg")
    else:
        plt.ylim((10, 85))
        plt.savefig("exp_mqtt_varying_delay_uniform.svg")
    plt.show()


def exchanged_bytes(cdf=False, boxplot=True):
    data_without = []
    data_rlc = []
    with open("dropper_run_10_without_3_2500.txt", "r") as fd:
        data = fd.readlines()
        for line in data:
            tab = line.split()
            if tab[-3] == "Total":  # Line indicating number of bytes
                data_without.append(int(tab[-1]))
    with open("dropper_run_10_rlc_2_2500.txt", "r") as fd:
        data = fd.readlines()
        for line in data:
            tab = line.split()
            if tab[-3] == "Total":
                data_rlc.append(int(tab[-1]))
    
    # Now separate in subtabs
    data_without_by_k = []
    for k in range(4):
        by_d = []
        for d in range(25):
            i = k * 26 + d
            by_d.append(data_without[i])
        data_without_by_k.append(by_d)
    
    data_rlc_by_k = []
    for k in range(4):
        by_d = []
        for d in range(25):
            i = k * 26 + d
            by_d.append(data_rlc[i])
            i += 1
        data_rlc_by_k.append(by_d)
    
    without_normalized = [[j/1000 for j in i] for i in data_without_by_k]
    rlc_normalized = [[j/1000 for j in i] for i in data_rlc_by_k]

    if boxplot:
        idxs_to_plot = np.arange(99, 89, -1)
        fig, (ax1, ax2) = plt.subplots(1, 2, sharey=True, figsize=(12,5))
        ax1.grid(axis="y")
        ax1.set_axisbelow(True)
        ax2.grid(axis="y")
        ax2.set_axisbelow(True)
        width = 0.5
        ax1.boxplot(without_normalized, positions=idxs_to_plot, showfliers=False)
        ax2.boxplot(rlc_normalized, positions=idxs_to_plot, showfliers=False)
        ax1.set_yscale("log")
        ax2.set_yscale("log")
        #for label in ax1.get_xticklabels()[1::2]:
        #    label.set_visible(False)
        #for label in ax2.get_xticklabels()[1::2]:
        #    label.set_visible(False)
        ax1.invert_xaxis()
        ax2.invert_xaxis()
        ax1.set_title("TCP")
        ax2.set_title("RLC")
        ax1.set_ylabel("Data sent [kB]")
        plt.subplots_adjust(wspace=0.05, hspace=0)

        # https://stackoverflow.com/questions/6963035/pyplot-axes-labels-for-subplots
        # add a big axes, hide frame
        fig.add_subplot(111, frameon=False)
        # hide tick and tick label of the big axes
        plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
        plt.grid(False)
        plt.xlabel("Value of the 'k' parameter of the Markov model")
        plt.savefig("figures/exp_mqtt_exchanged_bytes_boxplot.svg")
        plt.show()
    else:

        fig, ax = plt.subplots()

        if not cdf:
            to_plot = np.array([99, 95, 93, 90])
            tp = [99, 95, 93, 90]
            idx_d = np.arange(0, 50, 2)
            tp_str = ["k=" + str(i) for i in tp]
            linestyles = ["-", "--", "-.", ":"]
            # Exists also: linestyle=(0, (5, 2, 1, 2))
            colors_without = ["lightcoral", "red", "firebrick", "darkred"]
            colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]

            p_without = []
            p_rlc = []
            print(without_normalized)
            
            for idx, i in enumerate(range(4)):
                p, = ax.plot(idx_d, without_normalized[i], color=colors_without[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx])
                p_without.append(p)
            for idx, i in enumerate(range(4)):
                p, = ax.plot(idx_d, rlc_normalized[i], color=colors_rlc[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx])
                p_rlc.append(p)
            
            # Dummy plots
            p5, = plt.plot([0], marker='None',
                linestyle='None', label='dummy-tophead')

            ax.set_xlabel("Value of the 'd' parameter of the Markov dropper model")
            ax.set_ylabel("Data sent [kB]")
            leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
                    ["TCP"] + tp_str + ["RLC"] + tp_str,
                    loc="best", ncol=2) # Two columns, vertical group labels

            ax.grid()
            ax.set_axisbelow(True)

            # plt.title("Data sent by the MQTT clients (+ the UDP traffic)\nDepending on k and d from the Markov loss model")
            #plt.ylim((150, 750))
            plt.savefig("figures/mqtt_bytes_exchanged.svg")
            plt.savefig("figures/mqtt_bytes_exchanged.png")
            plt.show()
        
        else:

            # Flatten lists
            without_normalized = [j for i in without_normalized for j in i]
            rlc_normalized = [j for i in rlc_normalized for j in i]

            # TCP without plugin without loss
            baseline = without_normalized[0]
            without_baseline = [(i / baseline) * 100 for i in without_normalized[1:]]
            rlc_baseline = [(i / baseline) * 100 for i in rlc_normalized]

            min_r = min(min(without_normalized), min(rlc_normalized)) - 1
            max_r = max(max(without_normalized), max(rlc_normalized)) + 1

            hist_without, bin_edges_without = np.histogram(without_baseline, bins=60, range=(0, 400), density=True)
            hist_with, bin_edges_with = np.histogram(rlc_baseline, bins=60, range=(0, 400), density=True)
            dx = bin_edges_without[1] - bin_edges_without[0]
            cdf_without = np.cumsum(hist_without) * dx
            cdf_with = np.cumsum(hist_with) * dx

            cdf_without_filtered = []
            cdf_rfc_filtered = []
            for i in cdf_without:
                if i < 0.0001:
                    cdf_without_filtered.append(-10)
                elif i > 99.999:
                    cdf_without_filtered.append(10)
                else:
                    cdf_without_filtered.append(i)
            for i in cdf_with:
                if i < 0.0001:
                    cdf_rfc_filtered.append(-10)
                elif i > 99.999:
                    cdf_rfc_filtered.append(10)
                else:
                    cdf_rfc_filtered.append(i)
            
            # Plot the baseline
            ax.plot([100, 100], [0, 1], color="black", linestyle=":", label="Baseline TCP", linewidth=3)

            ax.plot(bin_edges_without[1:], cdf_without_filtered, label="TCP", color="red", linestyle="-")
            ax.plot(bin_edges_with[1:], cdf_rfc_filtered, label="RLC", color="darkblue", linestyle="-.")

            ax.set_xlabel("Data sent compared to the TCP baseline (i.e. without loss) [%]")
            ax.set_ylabel("CDF")
            plt.legend()
            plt.ylim((0, 1))
            # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

            ax.grid()
            ax.set_axisbelow(True)

            # plt.title("Data sent by the MQTT clients (+ the UDP traffic)\nDepending on k and d from the Markov loss model")
            # plt.ylim((min_r, max_r))
            plt.savefig("figures/mqtt_bytes_exchanged_cdf.svg")
            plt.savefig("figures/mqtt_bytes_exchanged_cdf.png")
            plt.show()


def analyze_point_plot_idx(boxplot):
    _, _, filenames_without = next(os.walk("results_without_2500/"))
    _, _, filenames_with = next(os.walk("results_rlc_2500/"))

    #for filename in filenames_without:
    #    rewrite_json(os.path.join("results_without_2500", filename))
    #for filename in filenames_with:
    #    rewrite_json(os.path.join("results_rlc_2500", filename))

    sorted_filenames_without = sorted(filenames_without, key=sort_list_by_idx)
    sorted_filenames_with = sorted(filenames_with, key=sort_list_by_idx)
    idxs_to_plot = np.arange(99, 89, -1)

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
    
    baseline = scrap_mqtt_json_multiple_run("results_without_2500/mqtt_res_run_10_-1.json")
    
    res_by_k = []
    for k in range(4):
        res_by_d = []
        for d in range(25):
            idx = k * 26 + d
            filename = sorted_filenames_without[idx]
            path = os.path.join("results_without_2500", filename)
            res_by_d.append(scrap_mqtt_json_multiple_run(path))
        res_by_k.append(res_by_d)
    
    res_by_k_rlc = []
    for k in range(4):
        res_by_d = []
        for d in range(25):
            idx = k * 26 + d
            filename = sorted_filenames_with[idx]
            path = os.path.join("results_rlc_2500", filename)
            res_by_d.append(scrap_mqtt_json_multiple_run(path))
        res_by_k_rlc.append(res_by_d)
    
    if boxplot:
        fig, (ax1, ax2) = plt.subplots(1, 2, sharey=True, figsize=(12,5))
        ax1.grid(axis="y")
        ax1.set_axisbelow(True)
        ax2.grid(axis="y")
        ax2.set_axisbelow(True)
        width = 0.5
        ax1.boxplot(res_by_k, positions=idxs_to_plot, showfliers=False)
        ax2.boxplot(res_by_k_rlc, positions=idxs_to_plot, showfliers=False)
        ax1.set_yscale("log")
        ax2.set_yscale("log")
        #for label in ax1.get_xticklabels()[1::2]:
        #    label.set_visible(False)
        #for label in ax2.get_xticklabels()[1::2]:
        #    label.set_visible(False)
        ax1.invert_xaxis()
        ax2.invert_xaxis()
        ax1.set_title("TCP")
        ax2.set_title("RLC")
        ax1.set_ylabel("Mean latency [ms]")
        plt.subplots_adjust(wspace=0.05, hspace=0)

        # https://stackoverflow.com/questions/6963035/pyplot-axes-labels-for-subplots
        # add a big axes, hide frame
        fig.add_subplot(111, frameon=False)
        # hide tick and tick label of the big axes
        plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
        plt.grid(False)
        plt.xlabel("Value of the 'k' parameter of the Markov model")
        plt.savefig("figures/exp_mqtt_latency_boxplot.svg")
        plt.show()
    else:
        to_plot = np.array([99, 95, 93, 90])
        idx_d = np.arange(0, 50, 2)
        tp = [99, 95, 93, 90]
        tp_str = ["k=" + str(i) for i in tp]
        linestyles = ["-", "--", "-.", ":"]
        colors_without = ["lightcoral", "red", "firebrick", "darkred"]
        colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]

        fig, ax = plt.subplots()
        ax.grid()
        ax.set_axisbelow(True)

        p_without = []
        p_rlc = []

        ax.plot([0, 49], [baseline] * 2, color="black", linestyle=":", label="Baseline TCP", linewidth=3)

        for idx, i in enumerate(range(4)):
            p, = ax.plot(idx_d, res_by_k[i], color=colors_without[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx])
            p_without.append(p)
        for idx, i in enumerate(range(4)):
            p, = ax.plot(idx_d, res_by_k_rlc[i], color=colors_rlc[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx])
            p_rlc.append(p)
            pass
        
        # Dummy plot
        p5, = plt.plot([0], marker='None',
            linestyle='None', label='dummy-tophead')

        ax.set_xlabel("Value of the 'd' parameter of the Markov dropper model")
        ax.set_ylabel("Mean latency [ms]")
        # plt.legend(ncol=2,handleheight=2.4, labelspacing=0.05)
        leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
                ["TCP"] + tp_str + ["RLC"] + tp_str,
                loc="best", ncol=2) # Two columns, vertical group labels

        plt.ylim((20, 60))
        # plt.title("Mean latency to send a MQTT message to the broker\nDepending on k and d from the Markov loss model")
        plt.savefig("figures/exp_mqtt_latency_99_95_93_90.svg")
        # plt.savefig("figures/mqtt_latency.png")
        plt.show()



def analyze_latency():
    _, _, filenames_without = next(os.walk("results_without_2500/"))
    _, _, filenames_with = next(os.walk("results_rlc_2500/"))
    # print(filenames_without)

    res_without = list()
    res_rlc = list()

    # I forgot to use JSON format so I need to scrapt like a n00b
    for filename in tqdm(sorted(filenames_without)):
        path = os.path.join("results_without_2500", filename)
        res_without.append(scrap_mqtt_json_multiple_run(path))

    # The same but for RLC
    for filename in tqdm(filenames_with):
        path = os.path.join("results_rlc_2500", filename)
        res_rlc.append(scrap_mqtt_json_multiple_run(path))
    
    print([int(i) for i in res_without if i > 50])

    min_r = min(min(res_without), min(res_rlc)) - 1
    max_r = max(max(res_without), max(res_rlc)) + 1

    hist_without, bin_edges_without = np.histogram(res_without, bins=60, range=(min_r, max_r), density=True)
    hist_with, bin_edges_with = np.histogram(res_rlc, bins=60, range=(min_r, max_r), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    cdf_with = np.cumsum(hist_with) * dx

    fig, ax = plt.subplots()
    ax.plot(bin_edges_without[1:], cdf_without, label="TCP", color="red", linestyle="-")
    ax.plot(bin_edges_with[1:], cdf_with, label="RLC", color="darkblue", linestyle="-.")

    ax.grid()
    ax.set_axisbelow(True)

    ax.set_ylabel("CDF")
    ax.set_xlabel("Latency [ms]")
    # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

    plt.legend(loc="best")
    plt.savefig("figures/exp_mqtt_latency_cdf.svg")
    plt.savefig("figures/exp_mqtt_latency_cdf.png")
    plt.show()



if __name__ == "__main__":
    # analyze_latency()
    # analyze_point_plot_same_K(90)
    # analyze_point_plot_same_D(2)
    # analyze_point_plot_idx(boxplot=False)
    exchanged_bytes(boxplot=False, cdf=True)
    # loss_varying_delay(True)