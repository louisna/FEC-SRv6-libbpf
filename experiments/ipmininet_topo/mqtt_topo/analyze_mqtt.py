import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import json
import os
import numpy as np
from tqdm import tqdm
import matplotlib.gridspec as gridspec
LATEX = False
if LATEX:
    import matplotlib
    matplotlib.use("pgf")
    matplotlib.rcParams.update({
        "pgf.texsystem": "pdflatex",
        'font.family': 'serif',
        'text.usetex': True,
        'pgf.rcfonts': False,
    })
    font_size = 18
    params = {
        'axes.labelsize': font_size, # fontsize for x and y labels (was 10)
        'axes.titlesize': font_size,
        #'text.fontsize': 11, # was 10
        # 'legend.fontsize': font_size, # was 10
        'legend.fontsize': font_size, # was 10
        'xtick.labelsize': font_size,
        'ytick.labelsize': font_size,
    }
    plt.rcParams.update(params)
    matplotlib.rcParams.update(params)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"

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
    
    return np.median(res_by_run)


def rewrite_json(filename):
    with open(filename, "r+") as fd:
        content = fd.read()
        fd.seek(0, 0)
        fd.write("[\n" + content + "]")
    

def json_multiple_run_mtm(filename):
    with open(filename, "r") as fd:
        data = json.load(fd)
    
    res_by_run = [run["totals"]["msg_time_mean_avg"] for run in data]
    return np.median(res_by_run)


def read_mqtt_run_json_all(filename):
    with open(filename, "r") as fd:
        data = json.load(fd)
    
    return [i["msg_time_mean"] for i in data["runs"]]


def sort_list_by_idx(filename):
    nb = filename.split("_")[-1].split(".")[0]
    return int(nb)


def sort_list_by_idx_simple(filename):
    nb = filename.split(".")[0]
    return int(nb)


def sort_list_by_double_idx(filename):
    delay = filename.split("_")[-2]
    idx = filename.split("_")[-1].split(".")[0]
    return int(delay) * 100 + int(idx)

def loss_varying_delay(MARKOV=True):
    if MARKOV:
        _, _, filenames_without = next(os.walk("results_09_06_delay/markov/without/"))
        _, _, filenames_with = next(os.walk("results_09_06_delay/markov/rlc_4_2/"))
        nb_exp = 21
        idxs_to_plot = np.arange(100, 89.5, -0.5)
    else:
        _, _, filenames_without = next(os.walk("results_09_06_delay/uniform/without/"))
        _, _, filenames_with = next(os.walk("results_09_06_delay/uniform/rlc_4_2/"))
        nb_exp = 21
        idxs_to_plot = np.arange(0, 10.5, 0.5)

    sorted_filenames_without = sorted(filenames_without, key=sort_list_by_idx_simple)
    sorted_filenames_rlc = sorted(filenames_with, key=sort_list_by_idx_simple)
    res_by_delay_without = []
    res_by_delay_rlc = []
    idx = 0
    for delay in [5, 10, 15]:
        if MARKOV:
            res_by_delay_without.append(mqtt_scrap_big(os.path.join("results_09_06_delay/markov/without/", sorted_filenames_without[idx])))
            res_by_delay_rlc.append(mqtt_scrap_big(os.path.join("results_09_06_delay/markov/rlc_4_2/", sorted_filenames_rlc[idx])))
        else:
            res_by_delay_without.append(mqtt_scrap_big(os.path.join("results_09_06_delay/uniform/without/", sorted_filenames_without[idx])))
            res_by_delay_rlc.append(mqtt_scrap_big(os.path.join("results_09_06_delay/uniform/rlc_4_2/", sorted_filenames_rlc[idx])))
        idx += 1
    
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)
    linestyles = ["-", "--", ":"]
    colors_without = ["lightcoral", "red", "firebrick", "darkred"]
    colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
    marker_without = ["<", ">", "^"]
    marker_rlc = ["d", "x", "X"]

    p_without = []
    p_rlc = []
    
    for idx, res_delay in enumerate(res_by_delay_without):
        p, = ax.plot(idxs_to_plot, res_delay, linestyle=linestyles[idx], color=colors_without[idx], marker=marker_without[idx])
        p_without.append(p)
    
    for idx, res_delay in enumerate(res_by_delay_rlc):
        p, = ax.plot(idxs_to_plot, res_delay, linestyle=linestyles[idx], color=colors_rlc[idx], marker=marker_rlc[idx])
        p_rlc.append(p)
    
    # Dummy plot
    p5, = plt.plot([0], marker='None',
           linestyle='None', label='dummy-tophead')

    if MARKOV:
        ax.set_xlabel("Value of the 'k' parameter of the Markov loss model")
    else:
        ax.set_xlabel("Value of the 'u' parameter of the Uniform loss model")
    ax.set_ylabel("Mean message time [ms]")
    lat_str = [str(i) + "ms" for i in [5, 10, 15]]
    leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
              ["TCP"] + lat_str + ["RLC"] + lat_str,
              loc=2, ncol=2) # Two columns, vertical group labels
    if MARKOV:
        plt.xlim((100.5, 89.5))
        plt.ylim((10, 70))
        plt.xticks(np.arange(90, 101, 1))
        plt.savefig("exp_mqtt_varying_delay_markov.pgf")
    else:
        plt.ylim((10, 70))
        plt.savefig("exp_mqtt_varying_delay_uniform.pgf")
    # plt.show()


def scrap_bytes(filename):
    with open(filename, "r") as fd:
        lines = fd.readlines()
    
    median_results = []

    counter = 0
    local_res = []
    for line in lines:
        if line.split()[-6] == "Total":
            if int(line.split()[-1]) >= 10000:
                val = int(line.split()[-1])
                if val < 900000:
                    val *= 5/4
                local_res.append(val)
            counter += 1
        if counter == 3:
            median_results.append(np.median(local_res))
            local_res = []
            counter = 0
    return median_results


def exchanged_bytes(cdf=False, boxplot=False):
    data_without = scrap_bytes("testons/dropper_without.txt")
    data_rlc = scrap_bytes("testons/dropper_rlc_4_2.txt")
    baseline = 921508
    
    max_val = 0
    min_val = 1000000000
    # Now separate in subtabs
    data_without_by_k = []
    for k in range(10):
        by_d = []
        for d in range(26):
            i = k * 26 + d
            by_d.append(data_without[i])
            max_val = max(max_val, data_without[i])
            min_val = max(min_val, data_without[i])
        data_without_by_k.append(by_d)
    
    data_rlc_by_k = []
    for k in range(10):
        by_d = []
        for d in range(26):
            i = k * 26 + d
            by_d.append(data_rlc[i])
            max_val = max(max_val, data_rlc[i])
            min_val = max(min_val, data_rlc[i])
        data_rlc_by_k.append(by_d)
    
    without_normalized = [[j/baseline for j in i] for i in data_without_by_k]
    rlc_normalized = [[j/baseline for j in i] for i in data_rlc_by_k]

    fig, ax = plt.subplots(figsize=(6.5, 4))  # figsize=(5, 2)

    if not cdf:
        to_plot = np.array([99, 95, 93, 90])
        tp = [99, 95, 93, 90]
        idx_d = np.arange(0, 51, 2)
        tp_str = ["k=" + str(i) for i in tp]
        linestyles = ["-", "--", "-.", ":"]
        # Exists also: linestyle=(0, (5, 2, 1, 2))
        colors_without = ["lightcoral", "red", "firebrick", "darkred"]
        colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
        marker_without = ["<", ">", "^", "v"]
        marker_rlc = ["d", "x", "X", "."]

        p_without = []
        p_rlc = []
        
        for idx, i in enumerate([0, 3, 6, 9]):
            p, = ax.plot(idx_d, [j * 100 for j in without_normalized[i]], color=colors_without[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx], marker=marker_without[idx])
            p_without.append(p)
        for idx, i in enumerate([0, 3, 6, 9]):
            p, = ax.plot(idx_d, [j * 100 for j in rlc_normalized[i]], color=colors_rlc[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx], marker=marker_rlc[idx])
            p_rlc.append(p)
        
        # Dummy plots
        p5, = plt.plot([0], marker='None',
            linestyle='None', label='dummy-tophead')

        ax.set_xlabel("Value of the 'd' parameter of the Markov model")
        ax.set_ylabel("Bytes sent compared to the TCP baseline [%]")
        print("okookkoko")
        leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
                ["TCP"] + tp_str + ["RLC"] + tp_str,
                loc=4, ncol=2) # Two columns, vertical group labels

        ax.grid()
        ax.set_axisbelow(True)

        # plt.title("Data sent by the MQTT clients (+ the UDP traffic)\nDepending on k and d from the Markov loss model")
        plt.ylim((-100, 300))
        # plt.savefig("figures/exp_mqtt_bytes_exchanged.pgf")
        plt.savefig("poster/mqtt_nb_bytes.pgf", transparent=True)
        # plt.show()
    
    else:

        # Flatten lists
        without_normalized = [j * 100 for i in without_normalized for j in i]
        rlc_normalized = [j * 100 for i in rlc_normalized for j in i]

        hist_without, bin_edges_without = np.histogram(without_normalized, bins=20000, range=(0, 400), density=True)
        hist_with, bin_edges_with = np.histogram(rlc_normalized, bins=20000, range=(0, 400), density=True)
        dx = bin_edges_without[1] - bin_edges_without[0]
        cdf_without = np.cumsum(hist_without) * dx
        dx = bin_edges_with[1] - bin_edges_with[0]
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

        ax.plot(bin_edges_without[1:], cdf_without_filtered, label="TCP", color="red", linestyle="-", linewidth=3)
        ax.plot(bin_edges_with[1:], cdf_rfc_filtered, label="RLC (+50%)", color="darkblue", linestyle="-.", linewidth=3)

        ax.set_xlabel("Bytes sent compared to the TCP baseline [%]")
        ax.set_ylabel("ECDF")
        plt.legend(loc=4)
        plt.ylim((0, 1))
        plt.xlim((50, 450))
        # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

        ax.grid()
        ax.set_axisbelow(True)
        plt.tight_layout()

        # plt.title("Data sent by the MQTT clients (+ the UDP traffic)\nDepending on k and d from the Markov loss model")
        # plt.ylim((min_r, max_r))
        # plt.savefig("figures/exp_mqtt_bytes_exchanged_cdf.pgf")
        # plt.savefig("figures/exp_mqtt_bytes_exchanged_cdf.pdf")
        plt.savefig("poster/mqtt_nb_bytes.pgf", transparent=True)
        # plt.show()


def scrap_nb_packets(filename):
    with open(filename, "r") as fd:
        lines = fd.readlines()
    
    median_results = []

    counter = 0
    local_res = []
    for line in lines:
        if line.split()[-6] == "Total":
            if int(line.split()[-3]) >= 5000:
                val = int(line.split()[-3])
                local_res.append(val)
                print(val)
            counter += 1
        if counter == 3:
            median_results.append(np.median(local_res))
            local_res = [] 
            counter = 0
    return median_results


def analyze_nb_packets(cdf=True):
    data_without = scrap_nb_packets("testons/dropper_without.txt")
    data_rlc = scrap_nb_packets("testons/dropper_rlc_4_2.txt")
    baseline = 5081

    # Now separate in subtabs
    data_without_by_k = []
    for k in range(10):
        by_d = []
        for d in range(26):
            i = k * 26 + d
            by_d.append((data_without[i] / baseline) * 100)
        data_without_by_k.append(by_d)
    
    data_rlc_by_k = []
    for k in range(10):
        by_d = []
        for d in range(26):
            i = k * 26 + d
            by_d.append((data_rlc[i] / baseline) * 100)
        data_rlc_by_k.append(by_d)
    
    fig, ax = plt.subplots(figsize=(6.5, 4))  # figsize=(5, 2)

    if cdf:
        # TCP without plugin without loss
        without_baseline = [(i / baseline) * 100 for i in data_without]
        rlc_baseline = [(i / baseline) * 100 for i in data_rlc]

        print(rlc_baseline)

        hist_without, bin_edges_without = np.histogram(without_baseline, bins=20000, range=(0, 300), density=True)
        hist_with, bin_edges_with = np.histogram(rlc_baseline, bins=20000, range=(0, 300), density=True)
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

        ax.plot(bin_edges_without[1:], cdf_without_filtered, label="TCP", color="red", linestyle="-", linewidth=3)
        ax.plot(bin_edges_with[1:], cdf_rfc_filtered, label="RLC (+50%)", color="darkblue", linestyle="-.", linewidth=3)

        ax.set_xlabel("Packets sent compared to the TCP baseline [%]")
        ax.set_ylabel("ECDF")
        plt.legend(loc=4)
        plt.ylim((0, 1))
        # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

        ax.grid()
        ax.set_axisbelow(True)
        plt.tight_layout()

        # plt.title("Data sent by the MQTT clients (+ the UDP traffic)\nDepending on k and d from the Markov loss model")
        # plt.ylim((min_r, max_r))
        # plt.savefig("figures/exp_mqtt_nb_packet_exchanged_cdf.pgf")
        # plt.savefig("figures/exp_mqtt_nb_packet_exchanged_cdf.pdf")
        # plt.show()
        plt.savefig("poster/mqtt_nb_packets.pgf", transparent=True)
    else:
        to_plot = np.array([99, 95, 93, 90])
        idx_d = np.arange(0, 51, 2)
        tp_str = ["k=" + str(i) for i in to_plot]
        linestyles = ["-", "--", "-.", ":"]
        # Exists also: linestyle=(0, (5, 2, 1, 2))
        colors_without = ["lightcoral", "red", "firebrick", "darkred"]
        colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
        marker_without = ["<", ">", "^", "v"]
        marker_rlc = ["d", "x", "X", "."]

        p_without = []
        p_rlc = []
        
        for idx, i in enumerate([0, 3, 6, 9]):
            p, = ax.plot(idx_d, data_without_by_k[i], color=colors_without[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx], marker=marker_without[idx])
            p_without.append(p)
        for idx, i in enumerate([0, 3, 6, 9]):
            p, = ax.plot(idx_d, data_rlc_by_k[i], color=colors_rlc[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx], marker=marker_rlc[idx])
            p_rlc.append(p)
        
        # Dummy plots
        p5, = plt.plot([0], marker='None',
            linestyle='None', label='dummy-tophead')

        ax.set_xlabel("Value of the 'd' parameter of the Markov dropper model")
        ax.set_ylabel("Packets sent compared to the TCP baseline [%]")
        leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
                ["TCP"] + tp_str + ["RLC"] + tp_str,
                loc="best", ncol=2) # Two columns, vertical group labels

        ax.grid()
        ax.set_axisbelow(True)

        # plt.title("Data sent by the MQTT clients (+ the UDP traffic)\nDepending on k and d from the Markov loss model")
        #plt.ylim((150, 750))
        # plt.savefig("figures/exp_mqtt_packets_exchanged.pgf")
        plt.savefig("figures/exp_mqtt_packets_exchanged.pdf")
        plt.show()


def analyze_point_plot_idx(boxplot):
    filenames_without = "testons/without/mqtt_res_run_0.json"
    filenames_with = "testons/rlc_4_2/mqtt_res_run_0.json"

    #for filename in filenames_without:
    #    rewrite_json(os.path.join("results_without_2500", filename))
    #for filename in filenames_with:
    #    rewrite_json(os.path.join("results_rlc_2500", filename))
    idxs_to_plot = np.arange(99, 89, -1)

    res_without = mqtt_scrap_big(filenames_without)
    res_rlc = mqtt_scrap_big(filenames_with)

    """# I forgot to use JSON format so I need to scrapt like a n00b
    for filename in tqdm(sorted_filenames_without):
        path = os.path.join("results_without_10", filename)
        res_without.append(read_mqtt_run_json_all(path))

    # The same but for RLC
    for filename in tqdm(sorted_filenames_with):
        path = os.path.join("results_rlc_3", filename)
        res_rlc.append(read_mqtt_run_json_all(path))"""
    
    baseline = 23  # scrap_mqtt_json_multiple_run("results_without_2500/mqtt_res_run_10_-1.json")
    
    res_by_k = []
    for k in range(10):
        res_by_d = []
        for d in range(26):
            idx = k * 26 + d
            res_by_d.append(res_without[idx])
        res_by_k.append(res_by_d)
    
    res_by_k_rlc = []
    for k in range(10):
        res_by_d = []
        for d in range(26):
            idx = k * 26 + d
            res_by_d.append(res_rlc[idx])
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
        idx_d = np.arange(0, 51, 2)
        tp = [99, 95, 93, 90]
        tp_str = ["k=" + str(i) for i in tp]
        linestyles = ["-", "--", "-.", ":"]
        colors_without = ["lightcoral", "red", "firebrick", "darkred"]
        colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
        marker_without = ["<", ">", "^", "v"]
        marker_rlc = ["d", "x", "X", "."]

        fig, ax = plt.subplots()
        ax.grid()
        ax.set_axisbelow(True)

        p_without = []
        p_rlc = []

        ax.plot([0, 50], [baseline] * 2, color="black", linestyle=":", label="Baseline TCP", linewidth=3)

        for idx, i in enumerate([0, 3, 6, 9]):
            p, = ax.plot(idx_d, res_by_k[i], color=colors_without[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx], marker=marker_without[idx])
            p_without.append(p)
        for idx, i in enumerate([0, 3, 6, 9]):
            p, = ax.plot(idx_d, res_by_k_rlc[i], color=colors_rlc[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx], marker=marker_rlc[idx])
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
        plt.savefig("figures/exp_mqtt_latency_99_95_93_90.pgf")
        # plt.savefig("figures/mqtt_latency.png")
        # plt.show()



def analyze_latency():
    _, _, filenames_without = next(os.walk("results_21_05/without/"))
    _, _, filenames_rlc_2 = next(os.walk("results_21_05/rlc_8_2/"))
    _, _, filenames_rlc_4 = next(os.walk("results_21_05/rlc_8_4/"))
    _, _, filenames_rlc_1 = next(os.walk("results_21_05/rlc_8_1/"))
    _, _, filenames_rlc_2_4 = next(os.walk("results_26_05/rlc_4_2/"))
    # print(filenames_without)

    res_without = list()
    res_rlc_2 = list()
    res_rlc_4 = list()
    res_rlc_1 = list()
    res_rlc_2_4 = list()

    # I forgot to use JSON format so I need to scrapt like a n00b
    for filename in tqdm(sorted(filenames_without)):
        path = os.path.join("results_26_05/without/", filename)
        res_without.append(scrap_mqtt_json_multiple_run(path))

    # The same but for RLC
    for filename in tqdm(filenames_rlc_2):
        path = os.path.join("results_21_05/rlc_8_2/", filename)
        res_rlc_2.append(scrap_mqtt_json_multiple_run(path))
    
    for filename in tqdm(filenames_rlc_4):
        path = os.path.join("results_21_05/rlc_8_4/", filename)
        res_rlc_4.append(scrap_mqtt_json_multiple_run(path))
    
    for filename in tqdm(filenames_rlc_1):
        path = os.path.join("results_21_05/rlc_8_1/", filename)
        res_rlc_1.append(scrap_mqtt_json_multiple_run(path))
    
    for filename in tqdm(filenames_rlc_2_4):
        path = os.path.join("results_26_05/rlc_4_2/", filename)
        res_rlc_2_4.append(scrap_mqtt_json_multiple_run(path))

    min_r = min([min(res_without), min(res_rlc_2), min(res_rlc_4), min(res_rlc_2_4), min(res_rlc_1)]) - 1
    max_r = max([max(res_without), max(res_rlc_2), max(res_rlc_4), max(res_rlc_2_4), max(res_rlc_1)]) + 1
    min_max_r = min([max(res_rlc_2), max(res_rlc_4), max(res_rlc_2_4), max(res_rlc_1)]) + 1
    print(min_max_r, min_r + 1)
    hist_without, bin_edges_without = np.histogram(res_without, bins=5000, range=(min_r, max_r), density=True)
    hist_rlc_2, bin_edges_rlc_2 = np.histogram(res_rlc_2, bins=5000, range=(min_r, max_r), density=True)
    hist_rlc_4, bin_edges_rlc_4 = np.histogram(res_rlc_4, bins=5000, range=(min_r, max_r), density=True)
    hist_rlc_1, bin_edges_rlc_1 = np.histogram(res_rlc_1, bins=5000, range=(min_r, max_r), density=True)
    hist_rlc_2_4, bin_edges_rlc_2_4 = np.histogram(res_rlc_2_4, bins=5000, range=(min_r, max_r), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    cdf_rlc_2 = np.cumsum(hist_rlc_2) * dx
    cdf_rlc_4 = np.cumsum(hist_rlc_4) * dx
    cdf_rlc_1 = np.cumsum(hist_rlc_1) * dx
    cdf_rlc_2_4 = np.cumsum(hist_rlc_2_4) * dx

    fig, ax = plt.subplots()  # figsize=(5, 2)
    ax.plot(bin_edges_without[1:], cdf_without, label="TCP", color="red", linestyle="-")
    ax.plot(bin_edges_rlc_1[1:], cdf_rlc_1, label="RLC 8 1", color="green", linestyle=(0, (3, 1, 1, 1)))
    ax.plot(bin_edges_rlc_2[1:], cdf_rlc_2, label="RLC 8 2", color="purple", linestyle="-.")
    ax.plot(bin_edges_rlc_4[1:], cdf_rlc_4, label="RLC 8 4", color="orange", linestyle="--")
    ax.plot(bin_edges_rlc_2_4[1:], cdf_rlc_2_4, label="RLC 4 2", color="darkblue", linestyle=(0, (1, 1)))

    ax.grid()
    ax.set_axisbelow(True)

    plt.ylabel("ECDF")
    plt.xlabel("Mean message time [ms]")
    # plt.tight_layout()
    # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

    plt.legend(loc="best")
    plt.savefig("figures/exp_mqtt_latency_cdf.pgf")
    # plt.show()


def sort_list_by_idx(filename):
    nb = filename.split("_")[-1].split(".")[0]
    return int(nb)


def varying_latency():
    _, _, filenames_without = next(os.walk("delay/without/"))
    _, _, filenames_rlc = next(os.walk("delay/rlc/"))

    sorted_filenames_rlc = sorted(filenames_without, key=sort_list_by_idx)
    sorted_filenames_xor = sorted(filenames_rlc, key=sort_list_by_idx)

    res_without = list()
    res_rlc = list()

    # I forgot to use JSON format so I need to scrapt like a n00b
    for filename in tqdm(sorted_filenames_rlc):
        path = os.path.join("delay/without", filename)
        res_without.append(json_multiple_run_mtm(path))

    # The same but for RLC
    for filename in tqdm(sorted_filenames_xor):
        path = os.path.join("delay/rlc", filename)
        res_rlc.append(json_multiple_run_mtm(path))
    
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)

    idx_delay = np.arange(5, 101, 5)

    ax.plot(idx_delay, res_without, label="TCP", color="red", marker="v")
    ax.plot(idx_delay, res_rlc, label="RLC", color="darkblue", linestyle="-.", marker="X")
    ax.set_xlabel("Delay on the rE-rD link [ms]")
    ax.set_ylabel("Mean message time [ms]")
    ax.set_xticks(np.arange(0, 101, 10))
    plt.legend(loc="lower right")
    plt.savefig("figures/varying_delay_100.pgf")
    # plt.show()


def mqtt_scrap_big(filename):
    print(filename)
    with open(filename, "r") as fd:
        data = json.load(fd)
    res = []
    for expe in data:
        tmp = []
        for run in expe:
            tmp.append(run["totals"]["msg_time_mean_avg"])
        res.append(np.median(tmp))
    return res


def analyze_latency_reproducible():
    filenames_without = "testons/without/mqtt_res_run_0.json"
    filenames_rlc_2 = "testons/rlc_8_2_3/mqtt_res_run_0.json"
    filenames_rlc_4 = "testons/rlc_8_4/mqtt_res_run_0.json"
    filenames_rlc_1 = "testons/rlc_8_1_3/mqtt_res_run_0.json"
    filenames_rlc_2_4 = "testons/rlc_4_2_2/mqtt_res_run_0.json"
    # print(filenames_without)

    res_without = mqtt_scrap_big(filenames_without)
    res_rlc_2 = mqtt_scrap_big(filenames_rlc_2)
    res_rlc_4 = mqtt_scrap_big(filenames_rlc_4)
    res_rlc_1 = mqtt_scrap_big(filenames_rlc_1)
    res_rlc_2_4 = mqtt_scrap_big(filenames_rlc_2_4)

    # Everything is in the same file

    min_r = min([min(res_without), min(res_rlc_2), min(res_rlc_4), min(res_rlc_2_4), min(res_rlc_1)]) - 1
    max_r = max([max(res_without), max(res_rlc_2), max(res_rlc_4), max(res_rlc_2_4), max(res_rlc_1)]) + 1
    min_max_r = min([max(res_rlc_2), max(res_rlc_4), max(res_rlc_2_4), max(res_rlc_1)]) + 1
    print(min_max_r, min_r + 1)
    hist_without, bin_edges_without = np.histogram(res_without, bins=5000, range=(min(res_without), max(res_without) + 1), density=True)
    hist_rlc_2, bin_edges_rlc_2 = np.histogram(res_rlc_2, bins=5000, range=(min(res_rlc_2), max(res_rlc_2) + 1), density=True)
    hist_rlc_4, bin_edges_rlc_4 = np.histogram(res_rlc_4, bins=5000, range=(min(res_rlc_4), max(res_rlc_4) + 1), density=True)
    hist_rlc_1, bin_edges_rlc_1 = np.histogram(res_rlc_1, bins=5000, range=(min(res_rlc_1), max(res_rlc_1) + 1), density=True)
    hist_rlc_2_4, bin_edges_rlc_2_4 = np.histogram(res_rlc_2_4, bins=5000, range=(min(res_rlc_2_4), max(res_rlc_2_4) + 1), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    dx = bin_edges_rlc_2[1] - bin_edges_rlc_2[0]
    cdf_rlc_2 = np.cumsum(hist_rlc_2) * dx
    dx = bin_edges_rlc_4[1] - bin_edges_rlc_4[0]
    cdf_rlc_4 = np.cumsum(hist_rlc_4) * dx
    dx = bin_edges_rlc_1[1] - bin_edges_rlc_1[0]
    cdf_rlc_1 = np.cumsum(hist_rlc_1) * dx
    dx = bin_edges_rlc_2_4[1] - bin_edges_rlc_2_4[0]
    cdf_rlc_2_4 = np.cumsum(hist_rlc_2_4) * dx

    fig, ax = plt.subplots(figsize=(8, 3.5))  # figsize=(5, 2)
    # plt.rcParams["font.family"] = "calibri"
    ax.plot(bin_edges_without[1:], cdf_without, label="TCP", color="red", linestyle="-", linewidth=3)
    ax.plot(bin_edges_rlc_1[1:], cdf_rlc_1, label="RLC 8 1", color="green", linestyle=(0, (3, 1, 1, 1)), linewidth=3)
    ax.plot(bin_edges_rlc_2[1:], cdf_rlc_2, label="RLC 8 2", color="darkgoldenrod", linestyle="-.", linewidth=3)
    ax.plot(bin_edges_rlc_4[1:], cdf_rlc_4, label="RLC 8 4", color="darkblue", linestyle="--", linewidth=3)
    ax.plot(bin_edges_rlc_2_4[1:], cdf_rlc_2_4, label="RLC 4 2", color="purple", linestyle=(0, (1, 1)), linewidth=3)

    ax.grid()
    ax.set_axisbelow(True)

    plt.ylabel("ECDF")
    plt.xlabel("Mean message time [ms]")
    plt.tight_layout()
    # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

    # plt.legend(loc="best")
    leg = plt.legend(loc="best", handlelength=3)
    plt.savefig("poster/mqtt_latency.pgf", transparent=True)
    # plt.savefig("figures/emqtt_latency_cdf.pdf")
    # plt.show()
    
def analyze_latency_reproducible_slides():
    filenames_without = "testons/without/mqtt_res_run_0.json"
    filenames_rlc_2 = "testons/rlc_8_2_3/mqtt_res_run_0.json"
    filenames_rlc_4 = "testons/rlc_8_4/mqtt_res_run_0.json"
    filenames_rlc_1 = "testons/rlc_8_1_3/mqtt_res_run_0.json"
    filenames_rlc_2_4 = "testons/rlc_4_2_2/mqtt_res_run_0.json"
    # print(filenames_without)

    res_without = mqtt_scrap_big(filenames_without)
    res_rlc_2 = mqtt_scrap_big(filenames_rlc_2)
    res_rlc_4 = mqtt_scrap_big(filenames_rlc_4)
    res_rlc_1 = mqtt_scrap_big(filenames_rlc_1)
    res_rlc_2_4 = mqtt_scrap_big(filenames_rlc_2_4)

    # Everything is in the same file

    min_r = min([min(res_without), min(res_rlc_2), min(res_rlc_4), min(res_rlc_2_4), min(res_rlc_1)]) - 1
    max_r = max([max(res_without), max(res_rlc_2), max(res_rlc_4), max(res_rlc_2_4), max(res_rlc_1)]) + 1
    min_max_r = min([max(res_rlc_2), max(res_rlc_4), max(res_rlc_2_4), max(res_rlc_1)]) + 1
    print(min_max_r, min_r + 1)
    hist_without, bin_edges_without = np.histogram(res_without, bins=5000, range=(min(res_without), max(res_without) + 1), density=True)
    hist_rlc_2, bin_edges_rlc_2 = np.histogram(res_rlc_2, bins=5000, range=(min(res_rlc_2), max(res_rlc_2) + 1), density=True)
    hist_rlc_4, bin_edges_rlc_4 = np.histogram(res_rlc_4, bins=5000, range=(min(res_rlc_4), max(res_rlc_4) + 1), density=True)
    hist_rlc_1, bin_edges_rlc_1 = np.histogram(res_rlc_1, bins=5000, range=(min(res_rlc_1), max(res_rlc_1) + 1), density=True)
    hist_rlc_2_4, bin_edges_rlc_2_4 = np.histogram(res_rlc_2_4, bins=5000, range=(min(res_rlc_2_4), max(res_rlc_2_4) + 1), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    dx = bin_edges_rlc_2[1] - bin_edges_rlc_2[0]
    cdf_rlc_2 = np.cumsum(hist_rlc_2) * dx
    dx = bin_edges_rlc_4[1] - bin_edges_rlc_4[0]
    cdf_rlc_4 = np.cumsum(hist_rlc_4) * dx
    dx = bin_edges_rlc_1[1] - bin_edges_rlc_1[0]
    cdf_rlc_1 = np.cumsum(hist_rlc_1) * dx
    dx = bin_edges_rlc_2_4[1] - bin_edges_rlc_2_4[0]
    cdf_rlc_2_4 = np.cumsum(hist_rlc_2_4) * dx

    fig, ax = plt.subplots()  # figsize=(5, 2)
    # plt.rcParams["font.family"] = "calibri"
    ax.plot(bin_edges_without[1:], cdf_without, label="TCP", color="red", linestyle="-")
    ax.plot(bin_edges_rlc_1[1:], cdf_rlc_1, label="RLC (+100% redundancy)", color="green", linestyle=(0, (3, 1, 1, 1)), linewidth=2)
    ax.plot(bin_edges_rlc_2[1:], cdf_rlc_2, label="RLC (+50% redundancy)", color="darkgoldenrod", linestyle="-.", linewidth=2)
    ax.plot(bin_edges_rlc_4[1:], cdf_rlc_4, label="RLC (+25% redundancy)", color="darkblue", linestyle="--", linewidth=2)
    # ax.plot(bin_edges_rlc_2_4[1:], cdf_rlc_2_4, label="RLC 4 2", color="purple", linestyle=(0, (1, 1)), linewidth=2)

    ax.grid()
    ax.set_axisbelow(True)

    plt.ylabel("ECDF")
    plt.xlabel("Mean message time [ms]")
    # plt.tight_layout()
    # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

    # plt.legend(loc="best")
    leg = plt.legend(loc="best", handlelength=3)
    # plt.savefig("figures/exp_mqtt_latency_cdf.pgf")
    plt.savefig("figures/exp_mqtt_latency_cdf.pdf")
    plt.show()


def analyze_latency_4_only(is_100=False):
    if is_100: s = "payload_100/"
    else: s = ""
    filenames_without = f"results_15_09/{s}without/mqtt_res_run_10.json"
    filenames_rlc_2_4 = f"results_15_09/{s}rlc_4_2/mqtt_res_run_10.json"
    filenames_rlc_2_8 = f"results_15_09/{s}rlc_8_2/mqtt_res_run_10.json"
    # print(filenames_without)

    res_without = mqtt_scrap_big(filenames_without)
    res_rlc_2_4 = mqtt_scrap_big(filenames_rlc_2_4)
    res_rlc_2_8 = mqtt_scrap_big(filenames_rlc_2_8)

    # Everything is in the same file

    min_r = min([min(res_without), min(res_rlc_2_4), min(res_rlc_2_8)]) - 1
    max_r = max([max(res_without), max(res_rlc_2_4), max(res_rlc_2_8)]) + 1
    min_max_r = min(max(res_rlc_2_4), max(res_rlc_2_8))
    print(min_max_r, min_r + 1)
    hist_without, bin_edges_without = np.histogram(res_without, bins=5000, range=(min(res_without), max(res_without) + 1), density=True)
    hist_rlc_2_4, bin_edges_rlc_2_4 = np.histogram(res_rlc_2_4, bins=5000, range=(min(res_rlc_2_4), max(res_rlc_2_4) + 1), density=True)
    hist_rlc_2_8, bin_edges_rlc_2_8 = np.histogram(res_rlc_2_8, bins=5000, range=(min(res_rlc_2_8), max(res_rlc_2_8) + 1), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    dx = bin_edges_rlc_2_4[1] - bin_edges_rlc_2_4[0]
    cdf_rlc_2_4 = np.cumsum(hist_rlc_2_4) * dx
    dx = bin_edges_rlc_2_8[1] - bin_edges_rlc_2_8[0]
    cdf_rlc_2_8 = np.cumsum(hist_rlc_2_8) * dx

    fig, ax = plt.subplots(figsize=(8, 3.5))  # figsize=(5, 2)
    # plt.rcParams["font.family"] = "calibri"
    ax.plot(bin_edges_without[1:], cdf_without, label="TCP", color="red", linestyle="-", linewidth=3)
    ax.plot(bin_edges_rlc_2_8[1:], cdf_rlc_2_8, label="RLC 8 2", color="green", linestyle="-", linewidth=3)
    ax.plot(bin_edges_rlc_2_4[1:], cdf_rlc_2_4, label="RLC 4 2", color="purple", linestyle=(0, (1, 1)), linewidth=3)

    ax.grid()
    ax.set_axisbelow(True)

    plt.ylabel("ECDF")
    plt.xlabel("Mean message time [ms]")
    if is_100: s = "100"
    else: s = "1000"
    plt.title(f"{s} bytes payload")
    plt.tight_layout()
    # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))

    # plt.legend(loc="best")
    if is_100: s = "100_"
    else: s = "1000_"
    leg = plt.legend(loc="best", handlelength=3)
    plt.savefig(f"figures/mqtt_v2_{s}_temp.png")
    # plt.savefig("poster/mqtt_latency.pgf", transparent=True)
    # plt.savefig("figures/emqtt_latency_cdf.pdf")
    plt.show()


if __name__ == "__main__":
    # analyze_latency()
    # analyze_latency_reproducible()
    analyze_latency_4_only(True)
    # analyze_latency_reproducible_slides()
    # varying_latency()
    # analyze_point_plot_same_K(90)
    # analyze_point_plot_same_D(2)
    # analyze_point_plot_idx(boxplot=False)
    # exchanged_bytes(boxplot=False, cdf=True)
    # loss_varying_delay(False)
    # analyze_nb_packets(cdf=True)