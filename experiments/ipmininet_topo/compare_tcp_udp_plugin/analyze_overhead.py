#!/bin/python3

import matplotlib.pyplot as plt
from pandas.io.pytables import DataCol
import numpy as np
import seaborn as sns
import os
import json
import yaml
from tqdm import tqdm
import pandas as pd


def sort_list_by_idx(filename):
    nb = filename.split("_")[-1].split(".")[0]
    return int(nb)


def plugin_overhead():
    ip6_len = 40
    srh_source_len = 8 + 16 + 16 + 16
    srh_repair_len = 8 + 16 + 16
    tlv_source_len = 8
    tlv_repair_len = 16
    udp_len = 8
    udp_payload = 10
    repair_payload = 106 + 8

    # Colors
    c_ip6 = "C1"
    c_srh_source = "C2"
    c_srh_repair = "C3"
    c_tlv_source = "C4"
    c_tlv_repair = "C5"
    c_udp = "C6"
    c_udp_payload = "C7"
    c_repair_payload = "C8"

    all_colors = [c_ip6, c_srh_source, c_srh_repair, c_tlv_source,
        c_tlv_repair, c_udp, c_udp_payload, c_repair_payload]

    # Names
    all_names = ["IPv6 Header", "Source Symbol SRH", "Repair Symbol SRH", "Source TLV", "Repair TLV",
        "UDP Header", "Payload", "Repair payload"]

    normal_udp = [udp_payload, udp_len, ip6_len]
    normal_udp_colors = [c_udp_payload, c_udp, c_ip6]
    source_udp = [udp_payload, udp_len, tlv_source_len, srh_source_len, ip6_len]
    source_udp_colors = [c_udp_payload, c_udp, c_tlv_source, c_srh_source, c_ip6]
    repair_udp = [repair_payload, udp_len, tlv_repair_len, srh_repair_len, ip6_len]
    repair_udp_colors = [c_repair_payload, c_udp, c_tlv_repair, c_srh_repair, c_ip6]

    normal_udp_bars = np.cumsum(normal_udp)
    source_udp_bars = np.cumsum(source_udp)
    repair_udp_bars = np.cumsum(repair_udp)

    fig, ax = plt.subplots()
    width = 0.5

    # Set style
    plt.style.use(['seaborn-paper', 'seaborn-whitegrid'])
    plt.style.use(['seaborn'])
    sns.set(palette='colorblind')
    colors = sns.color_palette(palette='colorblind')
    
    for elem, color in zip(reversed(normal_udp_bars), reversed(normal_udp_colors)):
        ax.bar(0, elem, width=0.5, color=color)
    
    for elem, color in zip(reversed(source_udp_bars), reversed(source_udp_colors)):
        ax.bar(1, elem, width=0.5, color=color)
    
    for elem, color in zip(reversed(repair_udp_bars), reversed(repair_udp_colors)):
        ax.bar(2, elem, width=0.5, color=color)

    # Plot for legend
    for color, name in zip(all_colors, all_names):
        plt.plot(-10, -10, color=color, label=name)
    
    
    plt.title("Overhead caused by the FEC plugin compared \nto a simple UDP packet (10 bytes payload)")
    plt.ylabel("Bytes of the packet")
    plt.xticks([0, 1, 2], ("UDP", "Source Symbol", "Repair Symbol"))
    ax.grid(axis="y")
    ax.set_axisbelow(True)
    plt.xlim((-0.5, 2.5))
    plt.ylim((0, 250))
    plt.legend(loc="best")
    plt.savefig("overhead.png")
    plt.savefig("overhead.svg")

    plt.show()


def scrap_cw(filename):
    with open(filename, "r") as fd:
        data = fd.readlines()
    
    # Skip 3 first lines and get the cw value
    # Only 45 lines to read
    res = []
    bytes_str = ["MBytes", "Bytes", "KBytes"]
    for line in data:
        if len(line.split()) == 0: continue
        if line.split()[-1] in bytes_str:
            scale = line.split()[-1]
            value = float(line.split()[-2])
            if scale == "KBytes":
                res.append(value)
            elif scale == "MBytes":
                res.append(value * 1000)
            else:
                res.append(value / 1000)   
    return res


def scrap_udp_loss(filename):
    with open(filename, "r") as fd:
        data = fd.readlines()
    res_loss = []
    total = 0
    for i, line in enumerate(data):
        if line.split()[0] == "Accepted":
            total += 1
            res_this_exp = []
            try:
                data_this_exp = data[i + 3:i + 3 + 29]
                for exp in data_this_exp:
                    percent = exp.split()[-1]
                    res_this_exp.append(max(0, float(percent.split("%")[0][1:])))
                res_loss.append(res_this_exp)
            except Exception:
                res_loss.append([])
        if total >= 100:
            break
    return res_loss


def scrap_total_time(filename):
    with open(filename, "r") as fd:
        data = fd.readlines()
    total_read = 0
    res_time = []
    res_retr = []
    for line in data:
        if len(line.split()) == 0: continue
        if line.split()[-1] == "sender":
            data_line = line.split()
            total_read += 1
            retr = int(data_line[-2])
            total_time = float(data_line[2].split("-")[1])
            res_time.append(total_time)
            res_retr.append(retr)
        if total_read == 3: break
    return np.median(res_retr), np.median(res_time)



def scrap_udp_jitter(filename):
    with open(filename, "r") as fd:
        data = fd.readlines()
    res_loss = []
    total = 0
    for i, line in enumerate(data):
        if line.split()[0] == "Accepted":
            total += 1
            res_this_exp = []
            try:
                data_this_exp = data[i + 3:i + 3 + 29]
                for exp in data_this_exp:
                    percent = exp.split()[-1]
                    res_this_exp.append(float(percent.split("%")[0][1:]))
                res_loss.append(res_this_exp)
            except Exception:
                continue  # Missing exp
        if total >= 100:
            break
    return res_loss


def json_tcp_time(filename):
    print(filename)
    with open(filename, "r") as fd:
        import re
        data = fd.readlines()
        data_string = "".join(data)
        data_clean = re.sub("}\n,\n]", "}\n]", data_string)
        data_clean = re.sub("}\n{", "}\n,\n{", data_clean)
        data_json = json.loads(data_clean)
    
    loss = []
    retr = []
    for run in data_json:
        try:
            loss.append(run["end"]["sum_received"]["seconds"])
            retr.append(run["end"]["sum_sent"]["retransmits"])
        except KeyError:
            continue
    return np.median(retr), np.median(loss)


def scrap_retransmission(filename):
    with open(filename, "r") as fd:
        data = fd.readlines()
    
    # Skip 3 first lines and get the cw value
    # Only 45 lines to read
    res = []
    bytes_str = ["MBytes", "Bytes", "KBytes"]
    for line in data:
        if len(line.split()) == 0: continue
        if line.split()[-1] in bytes_str:  # Line of interest
            retr = line.split  
    return res
        

def analyze_tpc_congestion_window_one():
    cw_without_filename = "tcp_markov_95_30/without.txt"
    cw_rlc_filename = "tcp_markov_95_30/rlc.txt"

    res_without = scrap_from_iperf_output(cw_without_filename)
    res_rlc = scrap_from_iperf_output(cw_rlc_filename)
    baseline_without = scrap_from_iperf_output("tcp_markov_95_30/baseline.txt")
    baseline_rlc = scrap_from_iperf_output("tcp_markov_95_30/baseline_rlc.txt")
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)

    p1, = ax.plot(res_without, color="darkred")
    p2, = ax.plot(res_rlc, color="darkblue")
    p3, = ax.plot(baseline_without, color="red")
    p4, = ax.plot(baseline_rlc, color="darkcyan")
    ax.set_xlabel("Runtime of the experiment [s]")
    ax.set_ylabel("TCP Congestion Window [kB]")
    p_without = [p1, p3]
    p_rlc = [p2, p4]
    tp_str = ["baseline", "k=95"]
    p5, = plt.plot([0], marker='None',
            linestyle='None', label='dummy-tophead')
    leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
                ["TCP"] + tp_str + ["RLC"] + tp_str,
                loc="best", ncol=2) # Two columns, vertical group labels

    plt.yscale("log")
    plt.show()


def analyze_tpc_congestion_window_all(analyze_function=scrap_cw, boxplot=False, min_max_ext=True):
    _, _, filenames_without = next(os.walk("results_09_05/tcp_quality_without/"))
    _, _, filenames_rlc = next(os.walk("results_09_05/tcp_quality_rlc/"))
    nb_exp = 19
    idxs_to_plot = np.arange(100, 89.5, -0.5)

    sorted_filenames_without = sorted(filenames_without, key=sort_list_by_idx)
    sorted_filenames_rlc = sorted(filenames_rlc, key=sort_list_by_idx)
    res_without = []
    res_rlc = []
    for filename in sorted_filenames_without:
        path = os.path.join("results_09_05/tcp_quality_without", filename)
        res_without.append(analyze_function(path))

    for filename in sorted_filenames_rlc:
        path = os.path.join("results_09_05/tcp_quality_rlc", filename)
        res_rlc.append(analyze_function(path))

    to_plot = np.array([99, 96, 93, 90])
    d_idx = np.arange(0, 50, 2)
    tp = [99, 96, 93, 90]
    tp_str = ["k=" + str(i) for i in tp]
    linestyles = ["-", "--", "-.", ":"]
    colors_without = ["lightcoral", "red", "firebrick", "darkred"]
    colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
    col_names = ["k=" + str(i) for i in tp]
    row_names = ["TCP", "RLC"]

    # Get by k
    cw_without_by_k = []
    cw_rlc_by_k = []
    for k in range(4):
        by_d = []
        by_d_rlc = []
        for d in range(25):
            idx = k * 26 + d
            by_d.append(res_without[idx])
            by_d_rlc.append(res_rlc[idx])
        cw_without_by_k.append(by_d)
        cw_rlc_by_k.append(by_d_rlc)

    if boxplot:
        fig, (ax) = plt.subplots(2, 4, sharey=True, sharex=True, figsize=(12, 5))
        for axl in ax:
            for axi in axl:
                axi.grid(axis="y")
                axi.set_axisbelow(True)

        for i, k in enumerate(cw_without_by_k):
            ax[0][i].boxplot(k, positions=d_idx, showfliers=False, widths=1.5)
            ax[0][i].set_yscale("log")
        for i, k in enumerate(cw_rlc_by_k):
            ax[1][i].boxplot(k, positions=d_idx, showfliers=False, widths=1.5)
            ax[1][i].set_yscale("log")
        for axl in ax:
            for axi in axl:
                for idx, label in enumerate(axi.get_xticklabels()):
                    if idx % 5 != 0:
                        label.set_visible(False)
        for axc, col in zip(ax[0], col_names):
            axc.set_title(col)
        for axr, row in zip(ax[:, 0], row_names):
            axr.set_ylabel(row)

        # https://stackoverflow.com/questions/6963035/pyplot-axes-labels-for-subplots
        # add a big axes, hide frame
        fig.add_subplot(111, frameon=False)
        # hide tick and tick label of the big axes
        plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
        plt.grid(False)
        plt.xlabel("Value of the 'd' parameter of the Markov model")
        # plt.ylabel("TCP Congestion Window [kB]")
        fig.tight_layout()
        fig.subplots_adjust(left=0.15, top=0.95)
        plt.savefig("figures/exp_tcp_congestion_window_boxplot.svg")
        plt.show()
    elif min_max_ext:
        
        plt.yscale("log")
        plt.show()
    else:
        fig, ax = plt.subplots()
        ax.grid()
        ax.set_axisbelow(True)

        p_without = []
        p_rlc = []

        p_without
        idx = 0
        for i, val in enumerate(idxs_to_plot):
            if val in to_plot:
                p, = ax.plot(res_without[i], color=colors_without[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx])
                p_without.append(p)
                p, = ax.plot(res_rlc[i], color=colors_rlc[idx], label=f"k={to_plot[idx]}", linestyle=linestyles[idx])
                p_rlc.append(p)
                idx += 1
        
        p5, = plt.plot([0], marker='None',
                linestyle='None', label='dummy-tophead')
        leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
                    ["TCP"] + tp_str + ["RLC"] + tp_str,
                    loc="best", ncol=2) # Two columns, vertical group labels
        ax.set_xlabel("Runtime of the experiment [s]")
        ax.set_ylabel("TCP Congestion Window [kB]")
        plt.yscale("log")
        plt.savefig("figures/exp_tcp_congestion_window.svg")
        plt.show()


def analyze_udp_loss(cdf=False, boxplot=False):
    filename_without = "sever_udp_without.txt"
    filename_rlc = "server_udp_rlc.txt"
    res_loss_without = scrap_udp_loss(filename_without)
    res_loss_rlc = scrap_udp_loss(filename_rlc)
    
    if cdf:
        fig, ax = plt.subplots()
        res_loss_without = [item for sublist in res_loss_without for item in sublist]
        res_loss_rlc = [item for sublist in res_loss_rlc for item in sublist]
        hist_without, bin_edges_without = np.histogram(res_loss_without, bins=60, range=(-1, 11.5), density=True)
        hist_with, bin_edges_with = np.histogram(res_loss_rlc, bins=60, range=(-1, 11.5), density=True)
        dx = bin_edges_without[1] - bin_edges_without[0]
        cdf_without = np.cumsum(hist_without) * dx
        cdf_with = np.cumsum(hist_with) * dx
    
        ax.plot(bin_edges_without[1:], cdf_without, label="UDP", color="red", linestyle="-")
        ax.plot(bin_edges_with[1:], cdf_with, label="RLC", color="darkblue", linestyle="-.")
        plt.show()
    elif boxplot:
        res_d_equal_30_without = []
        res_d_equal_30_rlc = []
        for k in range(10):
            for d in range(10):
                if d != 6: continue
                idx = k * 10 + d
                elem_without = res_loss_without[idx]
                res_d_equal_30_without.append(elem_without)
                elem_rlc = res_loss_rlc[idx]
                res_d_equal_30_rlc.append(elem_rlc)
        #plt.boxplot(res_d_equal_30_without)
        plt.boxplot(res_d_equal_30_rlc)
        plt.show()


def analyze_tcp_quality():
    _, _, filenames_without = next(os.walk("results_09_05/tcp_quality_without/"))
    _, _, filenames_rlc = next(os.walk("results_09_05/tcp_quality_rlc/"))

    sorted_filenames_without = sorted(filenames_without, key=sort_list_by_idx)
    sorted_filenames_rlc = sorted(filenames_rlc, key=sort_list_by_idx)

    time_without = []
    retr_without = []
    time_rlc = []
    retr_rlc = []
    for filename in sorted_filenames_without:
        path = os.path.join("results_09_05/tcp_quality_without", filename)
        retr, time = scrap_total_time(path)
        time_without.append(time)
        retr_without.append(retr)
    for filename in sorted_filenames_rlc:
        path = os.path.join("results_09_05/tcp_quality_rlc", filename)
        retr, time = scrap_total_time(path)
        time_rlc.append(time)
        retr_rlc.append(retr)
    
    baseline_retr, baseline_time = scrap_total_time("results_09_05/mqtt_res_run_10_baseline.json")
    
    # Get by k
    time_without_by_k = []
    time_rlc_by_k = []
    for k in range(4):
        by_d = []
        by_d_rlc = []
        for d in range(25):
            idx = k * 26 + d
            by_d.append(time_without[idx])
            by_d_rlc.append(time_rlc[idx])
        time_without_by_k.append(by_d)
        time_rlc_by_k.append(by_d_rlc)
    
    # Plot args
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)
    k_idx = [99, 96, 93, 90]
    d_idx = np.arange(0, 50, 2)
    tp_str = ["k=" + str(i) for i in k_idx]  # Legend string
    linestyles = ["-", "--", "-.", ":"]
    colors_without = ["lightcoral", "red", "firebrick", "darkred"]
    colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
    p_without = []  # Legend link
    p_rlc = []

    plt.plot([0, 48], [baseline_time - 0.5] * 2, color="black")
    
    for i, k in enumerate(time_without_by_k):
        p, = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_without[i])
        p_without.append(p)
        pass
    for i, k in enumerate(time_rlc_by_k):
        p, = plt.plot(d_idx, [j + (i + 1) * 0.5 for j in k], linestyle=linestyles[i], color=colors_rlc[i])
        p_rlc.append(p)
        pass
    
    # Dummy plot
    p5, = plt.plot([0], marker='None',
        linestyle='None', label='dummy-tophead')

    ax.set_xlabel("Value of the 'd' parameter of the Markov dropper model")
    ax.set_ylabel("Completion time [s]")
    # plt.legend(ncol=2,handleheight=2.4, labelspacing=0.05)
    leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
            ["TCP"] + tp_str + ["RLC"] + tp_str,
            loc=2, ncol=2) # Two columns, vertical group labels
        
    # plt.ylim((15, 100))
    #plt.yscale("log")
    plt.savefig("figures/tcp_quality_time.svg")
    plt.show()


def analyze_retransmission():
    _, _, filenames_without = next(os.walk("results_09_05/tcp_quality_without/"))
    _, _, filenames_rlc = next(os.walk("results_09_05/tcp_quality_rlc/"))

    sorted_filenames_without = sorted(filenames_without, key=sort_list_by_idx)
    sorted_filenames_rlc = sorted(filenames_rlc, key=sort_list_by_idx)

    time_without = []
    retr_without = []
    time_rlc = []
    retr_rlc = []
    for filename in sorted_filenames_without:
        path = os.path.join("results_09_05/tcp_quality_without", filename)
        retr, time = scrap_total_time(path)
        time_without.append(time)
        retr_without.append(retr)
    for filename in sorted_filenames_rlc:
        path = os.path.join("results_09_05/tcp_quality_rlc", filename)
        retr, time = scrap_total_time(path)
        time_rlc.append(time)
        retr_rlc.append(retr)
    
    baseline_retr, baseline_time = scrap_total_time("results_09_05/mqtt_res_run_10_baseline.json")
    
    # Get by k
    retr_without_by_k = []
    retr_rlc_by_k = []
    for k in range(4):
        by_d = []
        by_d_rlc = []
        for d in range(25):
            idx = k * 26 + d
            by_d.append(retr_without[idx])
            by_d_rlc.append(retr_rlc[idx])
        retr_without_by_k.append(by_d)
        retr_rlc_by_k.append(by_d_rlc)
    
    # Plot args
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)
    k_idx = [99, 96, 93, 90]
    d_idx = np.arange(0, 50, 2)
    tp_str = ["k=" + str(i) for i in k_idx]
    linestyles = ["-", "--", "-.", ":"]
    colors_without = ["lightcoral", "red", "firebrick", "darkred"]
    colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
    p_without = []  # Legend link
    p_rlc = []

    plt.plot([0, 48], [baseline_retr] * 2, color="black")

    for i, k in enumerate(retr_without_by_k):
        p, = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_without[i])
        p_without.append(p)
    for i, k  in enumerate(retr_rlc_by_k):
        p,  = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_rlc[i])
        p_rlc.append(p)
    
    # Dummy plot
    p5, = plt.plot([0], marker='None',
        linestyle='None', label='dummy-tophead')

    ax.set_xlabel("Value of the 'd' parameter of the Markov dropper model")
    ax.set_ylabel("Number of retransmission during the connection")
    # plt.legend(ncol=2,handleheight=2.4, labelspacing=0.05)
    leg3 = plt.legend([p5] + p_without + [p5] + p_rlc,
            ["TCP"] + tp_str + ["RLC"] + tp_str,
            loc=2, ncol=2) # Two columns, vertical group labels
        
    # plt.ylim((15, 100))
    # plt.yscale("log")
    plt.savefig("figures/exp_tcp_retransmissions.svg")
    plt.show()


def json_udp_loss(filename, jitter=False):
    with open(filename, "r") as fd:
        import re
        data = fd.readlines()
        data_string = "".join(data)
        data_clean = re.sub("}\n,\n]", "}\n]", data_string)
        data_json = json.loads(data_clean)
    
    loss = []
    for run in data_json:
        try:
            if jitter:
                loss.append(run["end"]["sum"]["jitter_ms"])
            else:
                loss.append(run["end"]["sum"]["lost_percent"])
        except KeyError:
            continue
    return np.median(loss)  


def analyze_udp_traffic(cdf=False, jitter=False):
    _, _, filenames_without = next(os.walk("results_13_05/udp_without/"))
    _, _, filenames_rlc = next(os.walk("results_13_05/udp_rlc/"))
    _, _, filenames_xor = next(os.walk("results_13_05/udp_xor/"))

    sorted_filenames_without = sorted(filenames_without, key=sort_list_by_idx)
    sorted_filenames_rlc = sorted(filenames_rlc, key=sort_list_by_idx)
    sorted_filenames_xor = sorted(filenames_xor, key=sort_list_by_idx)

    loss_without = []
    loss_rlc = []
    loss_xor = []

    for filename in tqdm(sorted_filenames_without):
        path = os.path.join("results_13_05/udp_without", filename)
        loss_without.append(json_udp_loss(path, jitter=jitter))
    
    for filename in tqdm(sorted_filenames_rlc):
        path = os.path.join("results_13_05/udp_rlc", filename)
        loss_rlc.append(json_udp_loss(path, jitter=jitter))
    
    for filename in tqdm(sorted_filenames_xor):
        path = os.path.join("results_13_05/udp_xor", filename)
        loss_xor.append(json_udp_loss(path, jitter=jitter))
    
    loss_without_by_k = []
    loss_rlc_by_k = []
    loss_xor_by_k = []

    for k in range(4):
        by_d_without = []
        by_d_rlc = []
        by_d_xor = []
        for d in range(26):
            idx = k * 26 + d
            by_d_without.append(loss_without[idx])
            by_d_rlc.append(loss_rlc[idx])
            by_d_xor.append(loss_xor[idx])
        loss_without_by_k.append(by_d_without)
        loss_rlc_by_k.append(by_d_rlc)
        loss_xor_by_k.append(by_d_xor)
    
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)

    print(loss_xor_by_k)

    if cdf:
        max_val = max([max(loss_without), max(loss_rlc), max(loss_xor)])
        hist_without, bin_edges_without = np.histogram(loss_without, bins=60, range=(0, max_val + 0.5), density=True)
        hist_rlc, bin_edges_rlc = np.histogram(loss_rlc, bins=60, range=(0, max_val + 0.5), density=True)
        hist_xor, bin_edges_xor = np.histogram(loss_xor, bins=60, range=(0, max_val + 0.5), density=True)
        dx = bin_edges_without[1] - bin_edges_without[0]
        cdf_without = np.cumsum(hist_without) * dx
        cdf_rlc = np.cumsum(hist_rlc) * dx
        cdf_xor = np.cumsum(hist_xor) * dx

        # Dummy values
        cdf_rlc = np.insert(cdf_rlc, 0, 0)
        cdf_without = np.insert(cdf_without, 0, 0)
        cdf_xor = np.insert(cdf_xor, 0, 0)
        bin_edges_rlc = [0] + bin_edges_rlc
        bin_edges_without = [0] + bin_edges_without
        bin_edges_xor = [0] + bin_edges_xor

        ax.plot(bin_edges_without, cdf_without, label="UDP", color="red", linestyle="-")
        ax.plot(bin_edges_rlc, cdf_rlc, label="RLC", color="darkblue", linestyle="-.")
        ax.plot(bin_edges_xor, cdf_xor, label="XOR", color="green", linestyle=":")
        if jitter:
            ax.set_xlabel("Jitter [ms]")
        else:
            ax.set_xlabel("Percentage of loss during the benchmark [%]")
        ax.set_ylabel("CDF")
        plt.legend(loc="best")
        if jitter:
            plt.savefig("figures/exp_udp_jitter_cdf.svg")
        else:
            plt.savefig("figures/exp_udp_loss_cdf.svg")
        plt.show()
    else:
        k_idx = [99, 96, 93, 90]
        d_idx = np.arange(0, 51, 2)
        tp_str = ["k=" + str(i) for i in k_idx]
        linestyles = ["-", "--", "-.", ":"]
        colors_without = ["lightcoral", "red", "firebrick", "darkred"]
        colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
        colors_xor = ["gold", "yellowgreen", "lightgreen", "darkgreen"]
        p_without = []  # Legend link
        p_rlc = []
        p_xor = []

        for i, k in enumerate(loss_without_by_k):
            p, = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_without[i])
            p_without.append(p)
        for i, k  in enumerate(loss_rlc_by_k):
            p,  = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_rlc[i])
            p_rlc.append(p)
        for i, k  in enumerate(loss_xor_by_k):
            p,  = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_xor[i])
            p_xor.append(p)

        # Dummy plot
        p5, = plt.plot([0], marker='None',
            linestyle='None', label='dummy-tophead')

        ax.set_xlabel("Value of the 'd' parameter of the Markov dropper model")
        if jitter:
            ax.set_ylabel("Jitter [ms]")
        else:    
            ax.set_ylabel("Percentage of loss during the benchmark [%]")
        # plt.legend(ncol=2,handleheight=2.4, labelspacing=0.05)
        leg3 = plt.legend([p5] + p_without + [p5] + p_rlc + [p5] + p_xor,
                ["TCP"] + tp_str + ["RLC"] + tp_str + ["XOR"] + tp_str,
                loc=2, ncol=3) # Two columns, vertical group labels
        if jitter:
            plt.savefig("figures/exp_udp_jitter.svg")
        else:
            plt.savefig("figures/exp_udp_loss.svg")
        plt.show()


def rlc_vs_udp():
    _, _, filenames_rlc = next(os.walk("results_13_05/udp_rlc/"))
    _, _, filenames_xor = next(os.walk("results_13_05/udp_xor/"))

    sorted_filenames_rlc = sorted(filenames_rlc, key=sort_list_by_idx)
    sorted_filenames_xor = sorted(filenames_rlc, key=sort_list_by_idx)

    loss_rlc = []
    jitt_rlc = []
    loss_xor = []
    jitt_xor = []
    
    for filename in tqdm(sorted_filenames_rlc):
        path = os.path.join("results_13_05/udp_rlc", filename)
        loss_rlc.append(100 - json_udp_loss(path, jitter=False))
        jitt_rlc.append(json_udp_loss(path, jitter=True))
    
    for filename in tqdm(sorted_filenames_xor):
        path = os.path.join("results_13_05/udp_xor", filename)
        loss_xor.append(100 - json_udp_loss(path, jitter=False))
        jitt_xor.append(json_udp_loss(path, jitter=True))
    
    # Compute ratio
    loss_rlc_xor = [i / j for i, j in zip(loss_rlc, loss_xor)]
    print(np.mean(loss_rlc_xor))
    jitt_rlc_xor = [i / j for i, j in zip(jitt_rlc, jitt_xor)]

    for ki, k in enumerate([99, 96, 93, 90]):
        for di, d in enumerate(np.arange(0, 51, 2)):
            i = ki * 26 + di
            print(k, d, ":", loss_xor[i], loss_rlc[i], "==", loss_rlc_xor[i])
    
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)

    max_val = max(max(loss_rlc_xor), max(jitt_rlc_xor))
    min_val = min(min(loss_rlc_xor), min(jitt_rlc_xor))
    hist_loss, bin_edges_loss = np.histogram(loss_rlc_xor, bins=60, range=(0.95, 1.2), density=True)
    hist_jitt, bin_edges_jitt = np.histogram(jitt_rlc_xor, bins=60, range=(0, 2), density=True)
    dx = bin_edges_loss[1] - bin_edges_loss[0]
    cdf_loss = np.cumsum(hist_loss) * dx
    cdf_jitt = np.cumsum(hist_jitt) * dx

    # Dummy values
    cdf_loss = np.insert(cdf_loss, 0, 0)
    cdf_jitt = np.insert(cdf_jitt, 0, 0)
    bin_edges_loss = [0] + bin_edges_loss
    bin_edges_jitt = [0] + bin_edges_jitt

    ax.plot(bin_edges_loss, cdf_loss, label="RLC/XOR", color="darkblue", linestyle="-")
    # ax.plot(bin_edges_jitt, cdf_jitt, label="jitter", color="green", linestyle="-.")

    ax.set_xlabel("Ratio RLC/XOR")
    ax.set_ylabel("CDF")
    plt.legend(loc="best")
    plt.savefig("figures/exp_udp_vs_loss_cdf.svg")
    plt.show()


def analyze_controller():
    file_without = "results_17_05/udp_without_95_30_rlc_std_1s.csv"
    file_control = "results_17_05/udp_controller_95_30_rlc_std_1s.csv"  # Oops it is in ms and not seconds

    data_without = pd.read_csv(file_without).values
    data_control = pd.read_csv(file_control).values

    idx_without = [i[0] for i in data_without]
    idx_control = [i[0] for i in data_control]

    val_without = [i[1] for i in data_without]
    val_control = [i[1] for i in data_control]

    # Must transform from 100ms to 1 sec oops => just for this run 
    val_control_sec = []
    idx_control_sec = []
    i = 0
    while i < len(val_control):
        val = 0
        idx = idx_control[i]
        for j in range(10):
            if i >= len(val_control): break
            val += val_control[i]
            i += 1
        val_control_sec.append(val)
        idx_control_sec.append(idx)
    
    # Replace oops
    val_control = val_control_sec
    idx_control = idx_control_sec

    fig, ax = plt.subplots()
    ax.plot(idx_without, val_without)
    ax.plot(idx_control, val_control)
    plt.ylim((170000, 350000))
    plt.show()
    


if __name__ == "__main__":
    # plugin_overhead()
    # analyze_tpc_congestion_window_all(scrap_cw, boxplot=True)
    # analyze_udp_loss(cdf=True, boxplot=True)
    # analyze_tcp_quality()
    # analyze_retransmission()
    # analyze_udp_traffic(cdf=True, jitter=False)
    # rlc_vs_udp()
    analyze_controller()