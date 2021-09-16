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
import matplotlib
import itertools
LATEX = True
if LATEX:
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
        'legend.fontsize': font_size, # was 10
        'xtick.labelsize': font_size,
        'ytick.labelsize': font_size,
    }
    plt.rcParams.update(params)
    matplotlib.rcParams.update(params)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"


def sort_list_by_idx(filename):
    if filename == ".DS_Store": return -1
    nb = filename.split("_")[-1].split(".")[0]
    return int(nb)


def plugin_overhead_slides():
    ip6_len = 40
    srh_source_len = 8 + 16 + 16 + 16
    srh_repair_len = 8 + 16 + 16
    tlv_source_len = 8
    tlv_repair_len = 16
    udp_len = 8
    tcp_len = 32
    mqtt_payload = 100
    repair_payload = mqtt_payload + ip6_len + srh_source_len + tcp_len
    
    # Colors
    palette = itertools.cycle(sns.color_palette("pastel"))
    c_ip6 = next(palette)
    c_srh_source = next(palette)
    c_srh_repair = next(palette)
    c_tlv_source = next(palette)
    c_tlv_repair = next(palette)
    c_udp = next(palette)
    c_mqtt_payload = next(palette)
    c_repair_payload = next(palette)
    c_tcp = next(palette)

    all_patterns = [ "/" , "\\" , "+" , "|" , "x" , "O", "o", "-", "."]
    # Patterns
    p_ip6 = all_patterns[0]
    p_srh_source = all_patterns[1]
    p_srh_repair = all_patterns[2]
    p_tlv_source = all_patterns[3]
    p_tlv_repair = all_patterns[4]
    p_udp = all_patterns[5]
    p_tcp = all_patterns[6]
    p_mqtt_payload = all_patterns[7]
    p_repair_payload = all_patterns[8]

    all_colors = [c_ip6, c_srh_source, c_srh_repair, c_tlv_source,
        c_tlv_repair, c_udp, c_tcp, c_mqtt_payload, c_repair_payload]

    # Names
    all_names = ["IPv6 Header", "Source Symbol SRH", "Repair Symbol SRH", "Source TLV", "Repair TLV",
        "UDP Header", "TCP Header", "MQTT Payload", "Repair payload"]

    all_legend = [True, True, False, True, False, False, True, True, False]

    normal_udp = [mqtt_payload, tcp_len, ip6_len]
    normal_udp_colors = [c_mqtt_payload, c_tcp, c_ip6]
    normal_pattern = [p_mqtt_payload, p_tcp, p_ip6]
    source_udp = [mqtt_payload, tcp_len, tlv_source_len, srh_source_len, ip6_len]
    source_udp_colors = [c_mqtt_payload, c_tcp, c_tlv_source, c_srh_source, c_ip6]
    source_pattern = [p_mqtt_payload, p_tcp, p_tlv_source, p_srh_source, p_ip6]
    repair_udp = [repair_payload, udp_len, tlv_repair_len, srh_repair_len, ip6_len]

    normal_udp_bars = np.cumsum(normal_udp)
    source_udp_bars = np.cumsum(source_udp)

    fig, ax = plt.subplots(figsize=(7, 4))  # figsize=(5, 2)
    width = 0.5
    ax.grid(b=True, which='major', linestyle='-', axis="y")
    ax.set_axisbelow(True)

    # Set style
    # plt.style.use(['seaborn-paper', 'seaborn-whitegrid'])
    # plt.style.use(['seaborn'])
    # sns.set(palette='colorblind')
    # colors = sns.color_palette(palette='colorblind')
    
    for elem, color, pattern in zip(reversed(normal_udp_bars), reversed(normal_udp_colors), reversed(normal_pattern)):
        ax.bar(0, elem, width=0.5, color=color, hatch=pattern, alpha=0.99)
    for elem, color, pattern in zip(reversed(normal_udp_bars), reversed(normal_udp_colors), reversed(normal_pattern)):
        ax.bar(0, elem, width=0.5, color="none", edgecolor="grey")
    
    for elem, color, pattern in zip(reversed(source_udp_bars), reversed(source_udp_colors), reversed(source_pattern)):
        ax.bar(1, elem, width=0.5, color=color, hatch=pattern, alpha=0.99)
    for elem, color, pattern in zip(reversed(source_udp_bars), reversed(source_udp_colors), reversed(source_pattern)):
        ax.bar(1, elem, width=0.5, color="none", edgecolor="grey")

    # Plot for legend
    for color, name, pattern, to_plot in zip(all_colors, all_names, all_patterns, all_legend):
        if to_plot:
            ax.bar(0, 0, width=0, color=color, label=name, hatch=pattern)
    
    
    # plt.title("Overhead caused by the FEC plugin for the MQTT benchmark")
    plt.ylabel("Size of the packet in bytes")
    plt.xticks([0, 1, 2], ("TCP", "Source\nSymbol", "Repair Symbol"))
    plt.xlim((-0.5, 1.5))
    plt.ylim((0, 300))
    # bbox_to_anchor=(1.04,1)
    leg = plt.legend(bbox_to_anchor=(1.04,1), loc="upper left", labelspacing=1.0, borderpad=1.2)
    for lh in leg.legendHandles:
        lh.set_alpha(0.99)
        lh.set_height(15.0)
    
    fig.tight_layout()

    if LATEX:
        # plt.savefig("exp_overhead.pgf", bbox_inches="tight")
        plt.savefig("../mqtt_topo/poster/mqtt_plugin_overhead.pgf", transparent=True)
    plt.savefig("exp_overhead.pdf", bbox_inches="tight")

    if not LATEX:
        plt.show()


def plugin_overhead():
    ip6_len = 40
    srh_source_len = 8 + 16 + 16 + 16
    srh_repair_len = 8 + 16 + 16
    tlv_source_len = 8
    tlv_repair_len = 16
    udp_len = 8
    tcp_len = 32
    mqtt_payload = 100
    repair_payload = mqtt_payload + ip6_len + srh_source_len + tcp_len
    
    # Colors
    palette = itertools.cycle(sns.color_palette("pastel"))
    c_ip6 = next(palette)
    c_srh_source = next(palette)
    c_srh_repair = next(palette)
    c_tlv_source = next(palette)
    c_tlv_repair = next(palette)
    c_udp = next(palette)
    c_mqtt_payload = next(palette)
    c_repair_payload = next(palette)
    c_tcp = next(palette)

    all_patterns = [ "/" , "\\" , "+" , "|" , "x" , "O", "o", "-", "."]
    # Patterns
    p_ip6 = all_patterns[0]
    p_srh_source = all_patterns[1]
    p_srh_repair = all_patterns[2]
    p_tlv_source = all_patterns[3]
    p_tlv_repair = all_patterns[4]
    p_udp = all_patterns[5]
    p_tcp = all_patterns[6]
    p_mqtt_payload = all_patterns[7]
    p_repair_payload = all_patterns[8]

    all_colors = [c_ip6, c_srh_source, c_srh_repair, c_tlv_source,
        c_tlv_repair, c_udp, c_tcp, c_mqtt_payload, c_repair_payload]

    # Names
    all_names = ["IPv6 Header", "Source Symbol SRH", "Repair Symbol SRH", "Source TLV", "Repair TLV",
        "UDP Header", "TCP Header", "MQTT Payload", "Repair payload"]
    

    normal_udp = [mqtt_payload, tcp_len, ip6_len]
    normal_udp_colors = [c_mqtt_payload, c_tcp, c_ip6]
    normal_pattern = [p_mqtt_payload, p_tcp, p_ip6]
    source_udp = [mqtt_payload, tcp_len, tlv_source_len, srh_source_len, ip6_len]
    source_udp_colors = [c_mqtt_payload, c_tcp, c_tlv_source, c_srh_source, c_ip6]
    source_pattern = [p_mqtt_payload, p_tcp, p_tlv_source, p_srh_source, p_ip6]
    repair_udp = [repair_payload, udp_len, tlv_repair_len, srh_repair_len, ip6_len]
    repair_udp_colors = [c_repair_payload, c_udp, c_tlv_repair, c_srh_repair, c_ip6]
    repair_pattern = [p_repair_payload, p_udp, p_tlv_repair, p_srh_repair, p_ip6]

    normal_udp_bars = np.cumsum(normal_udp)
    source_udp_bars = np.cumsum(source_udp)
    repair_udp_bars = np.cumsum(repair_udp)

    fig, ax = plt.subplots()
    width = 0.5
    ax.grid(b=True, which='major', linestyle='-', axis="y")
    ax.set_axisbelow(True)

    # Set style
    # plt.style.use(['seaborn-paper', 'seaborn-whitegrid'])
    # plt.style.use(['seaborn'])
    # sns.set(palette='colorblind')
    # colors = sns.color_palette(palette='colorblind')
    
    for elem, color, pattern in zip(reversed(normal_udp_bars), reversed(normal_udp_colors), reversed(normal_pattern)):
        ax.bar(0, elem, width=0.5, color=color, hatch=pattern, alpha=0.99)
    for elem, color, pattern in zip(reversed(normal_udp_bars), reversed(normal_udp_colors), reversed(normal_pattern)):
        ax.bar(0, elem, width=0.5, color="none", edgecolor="grey")
    
    for elem, color, pattern in zip(reversed(source_udp_bars), reversed(source_udp_colors), reversed(source_pattern)):
        ax.bar(1, elem, width=0.5, color=color, hatch=pattern, alpha=0.99)
    for elem, color, pattern in zip(reversed(source_udp_bars), reversed(source_udp_colors), reversed(source_pattern)):
        ax.bar(1, elem, width=0.5, color="none", edgecolor="grey")
    
    for elem, color, pattern in zip(reversed(repair_udp_bars), reversed(repair_udp_colors), reversed(repair_pattern)):
        ax.bar(2, elem, width=0.5, color=color, hatch=pattern, alpha=0.99)
    for elem, color, pattern in zip(reversed(repair_udp_bars), reversed(repair_udp_colors), reversed(repair_pattern)):
        ax.bar(2, elem, width=0.5, color="none", edgecolor="grey")

    # Plot for legend
    for color, name, pattern in zip(all_colors, all_names, all_patterns):
        ax.bar(0, 0, width=0, color=color, label=name, hatch=pattern)
    
    
    plt.title("Overhead caused by the FEC plugin for the MQTT benchmark")
    plt.ylabel("Size of the packet in bytes")
    plt.xticks([0, 1, 2], ("TCP", "Source Symbol", "Repair Symbol"))
    plt.xlim((-0.5, 2.5))
    plt.ylim((0, 400))
    # bbox_to_anchor=(1.04,1)
    leg = plt.legend(bbox_to_anchor=(1.04,1), loc="upper left", labelspacing=1.0, borderpad=1.2)
    for lh in leg.legendHandles:
        lh.set_alpha(0.99)
        lh.set_height(15.0)
    
    if LATEX:
        plt.savefig("exp_overhead.pgf", bbox_inches="tight")
    plt.savefig("exp_overhead.pdf", bbox_inches="tight")

    if not LATEX:
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
    row_names = ["Cwnd (KBytes)", "Cwnd (KBytes)"]

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
        # fig.subplots_adjust(left=0.15, top=0.95)
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
        if filename == ".DS_Store": continue
        path = os.path.join("results_13_05/udp_without", filename)
        loss_without.append(json_udp_loss(path, jitter=jitter))
    
    for filename in tqdm(sorted_filenames_rlc):
        if filename == ".DS_Store": continue
        path = os.path.join("results_13_05/udp_rlc", filename)
        loss_rlc.append(json_udp_loss(path, jitter=jitter))
    
    for filename in tqdm(sorted_filenames_xor):
        if filename == ".DS_Store": continue
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
    
    fig, ax = plt.subplots(figsize=(6.5, 3.5))  # figsize=(5, 2)
    ax.grid()
    ax.set_axisbelow(True)

    if cdf:
        max_val = max([max(loss_without), max(loss_rlc), max(loss_xor)])
        print(loss_without)
        n_bins = 1000
        hist_without, bin_edges_without = np.histogram(loss_without, bins=n_bins, range=(min(loss_without), max(loss_without) + 0.01), density=True)
        hist_rlc, bin_edges_rlc = np.histogram(loss_rlc, bins=n_bins, range=(min(loss_rlc), max(loss_rlc) + 0.01), density=True)
        hist_xor, bin_edges_xor = np.histogram(loss_xor, bins=n_bins, range=(min(loss_xor), max(loss_xor) + 0.01), density=True)
        dx = bin_edges_without[1] - bin_edges_without[0]
        cdf_without = np.cumsum(hist_without) * dx
        dx = bin_edges_rlc[1] - bin_edges_rlc[0]
        cdf_rlc = np.cumsum(hist_rlc) * dx
        dx = bin_edges_xor[1] - bin_edges_xor[0]
        cdf_xor = np.cumsum(hist_xor) * dx

        # Dummy values
        cdf_rlc = np.insert(cdf_rlc, 0, 0)
        cdf_without = np.insert(cdf_without, 0, 0)
        cdf_xor = np.insert(cdf_xor, 0, 0)
        bin_edges_rlc = [0] + bin_edges_rlc
        bin_edges_without = [0] + bin_edges_without
        bin_edges_xor = [0] + bin_edges_xor

        ax.plot(bin_edges_without, cdf_without, label="UDP", color="red", linestyle="-", linewidth=3)
        ax.plot(bin_edges_rlc, cdf_rlc, label="RLC (+50%)", color="darkblue", linestyle="-.", linewidth=3)
        ax.plot(bin_edges_xor, cdf_xor, label="XOR (+50%)", color="green", linestyle="--", linewidth=3)
        if jitter:
            ax.set_xlabel("Jitter [ms]")
        else:
            ax.set_xlabel("Loss during the benchmark [%]")
        ax.set_ylabel("ECDF")
        plt.legend(loc="best")
        plt.tight_layout()
        if jitter:
            plt.savefig("figures/exp_udp_jitter_cdf.pgf")
        else:
            # plt.savefig("figures/exp_udp_loss_cdf.pgf")
            plt.savefig("../mqtt_topo/poster/udp_loss.pgf", transparent=True)
        # plt.show()
        #plt.plot(loss_without)
        #plt.show()
    else:
        k_idx = [99, 96, 93, 90]
        d_idx = np.arange(0, 51, 2)
        tp_str = ["k=" + str(i) for i in k_idx]
        linestyles = ["-", "--", "-.", ":"]
        colors_without = ["lightcoral", "red", "firebrick", "darkred"]
        colors_rlc = ["slategrey", "darkcyan", "royalblue", "darkblue"]
        colors_xor = ["gold", "yellowgreen", "lightgreen", "darkgreen"]
        marker_without = ["<", ">", "^", "v"]
        marker_rlc = ["d", "x", "X", "."]
        marker_xor = ["1", "2", "3", "4"]
        p_without = []  # Legend link
        p_rlc = []
        p_xor = []

        for i, k in enumerate(loss_without_by_k):
            p, = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_without[i], marker=marker_without[i])
            p_without.append(p)
        for i, k  in enumerate(loss_rlc_by_k):
            p,  = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_rlc[i], marker=marker_rlc[i])
            p_rlc.append(p)
        for i, k  in enumerate(loss_xor_by_k):
            p,  = plt.plot(d_idx, k, linestyle=linestyles[i], color=colors_xor[i], marker=marker_xor[i])
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
                ["UDP"] + tp_str + ["RLC"] + tp_str + ["XOR"] + tp_str,
                loc=2, ncol=3) # Two columns, vertical group labels
        if jitter:
            plt.savefig("figures/exp_udp_jitter.pgf")
        else:
            plt.savefig("figures/exp_udp_loss.pgf")
        # plt.show()


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
    filename_without_hd = "results_17_05/udp_without_95_30_rlc_std_1s_hD.csv"
    filename_control_hd = "results_17_05/udp_controller_95_30_rlc_std_1s_hD.csv"

    data_without = pd.read_csv(file_without).values
    data_control = pd.read_csv(file_control).values
    data_without_hd = pd.read_csv(filename_without_hd).values
    data_control_hd = pd.read_csv(filename_control_hd).values

    idx_without = [i[0] for i in data_without]
    idx_control = [i[0] for i in data_control]
    idx_without_hd = [i[0] for i in data_without_hd]
    idx_control_hd = [i[0] for i in data_control_hd]

    val_without = [i[1] / 1000 for i in data_without]
    val_control = [i[1] / 1000 for i in data_control]
    val_without_hd = [i[1] / 1000 for i in data_without_hd]
    val_control_hd = [i[1] / 1000 for i in data_control_hd]

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

    fig, ax = plt.subplots(figsize=(6.5, 4))
    ax.grid()
    ax.set_axisbelow(True)

    p_control = []
    p_without = []
    p, = ax.plot(idx_without, val_without, color="blue", label="rE", linewidth=4)
    p_without.append(p)
    p, = ax.plot(idx_control, val_control, linestyle="-", color="darkorange", label="rE", linewidth=2)
    p_control.append(p)
    p, = ax.plot(idx_without_hd, val_without_hd, linestyle="-", color="green", label="hD", linewidth=4)
    p_without.append(p)
    p, = ax.plot(idx_control_hd, val_control_hd, linestyle="-", color="red", label="hD", linewidth=2)
    p_control.append(p)
    """ p5, = plt.plot([0], marker='None',
                linestyle='None', label='dummy-tophead')
    leg3 = plt.legend([p5] + p_without + [p5] + p_control,
                    ["SRv6-FEC"] + ["protected link", "server"] + ["SRv6-FEC + Controller"] + ["protected link", "server"],
                    loc="best", ncol=2) # Two columns, vertical group labels """
    ax.set_xlabel("Time [s]")
    ax.set_ylabel("KBytes/second received")
    plt.ylim((140, 380))
    plt.tight_layout()
    # plt.savefig("figures/exp_controller_udp.pgf")
    if LATEX:
        plt.savefig("../mqtt_topo/poster/controller_udp.pgf", transparent=True)
    # plt.savefig("figures/exp_controller_udp.pdf")
    else: plt.show()


def controller_by_k():
    dir_std = "results_18_05/standard/"
    dir_ctr = "results_18_05/controller"
    _, _, filenames_std = next(os.walk(dir_std))
    _, _, filenames_ctr = next(os.walk(dir_ctr))

    sorted_filenames_std = sorted(filenames_std, key=sort_list_by_idx)
    sorted_filenames_ctr = sorted(filenames_ctr, key=sort_list_by_idx)

    loss_std = []
    loss_ctr = []

    for filename in tqdm(sorted_filenames_std):
        path = os.path.join(dir_std, filename)
        loss_std.append(json_udp_loss(path, jitter=False))
    
    for filename in tqdm(sorted_filenames_ctr):
        path = os.path.join(dir_ctr, filename)
        loss_ctr.append(json_udp_loss(path, jitter=False))
    
    fig, ax = plt.subplots()
    
    ax.plot(loss_std)
    ax.plot(loss_ctr)
    plt.ylim((-1, 16.5))
    plt.show()


def analyze_controller_udp_traffic(cdf=False, jitter=False):
    _, _, filenames_std = next(os.walk("results_18_05/udp_controller/standard"))
    _, _, filenames_ctr = next(os.walk("results_18_05/udp_controller/controller"))

    sorted_filenames_std = sorted(filenames_std, key=sort_list_by_idx)
    sorted_filenames_ctr = sorted(filenames_ctr, key=sort_list_by_idx)

    loss_std = []
    loss_ctr = []

    for filename in tqdm(sorted_filenames_std):
        path = os.path.join("results_18_05/udp_controller/standard", filename)
        loss_std.append(json_udp_loss(path, jitter=jitter))
    
    for filename in tqdm(sorted_filenames_ctr):
        path = os.path.join("results_18_05/udp_controller/controller", filename)
        loss_ctr.append(json_udp_loss(path, jitter=jitter))
    
    loss_std_by_k = []
    loss_ctr_by_k = []

    for k in range(4):
        by_d_std = []
        by_d_ctr = []
        for d in range(26):
            idx = k * 26 + d
            by_d_std.append(loss_std[idx])
            by_d_ctr.append(loss_ctr[idx])
        loss_std_by_k.append(by_d_std)
        loss_ctr_by_k.append(by_d_ctr)
    
    baseline = json_udp_loss("results_18_05/udp_controller/baseline.json", jitter=jitter)
    
    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)

    if cdf:
        max_val = max([max(loss_std), max(loss_ctr)])
        hist_std, bin_edges_std = np.histogram(loss_std, bins=10000, range=(min(loss_std), max(loss_std) + 0.1), density=True)
        hist_ctr, bin_edges_ctr = np.histogram(loss_ctr, bins=10000, range=(min(loss_ctr), max(loss_ctr) + 0.1), density=True)
        dx = bin_edges_std[1] - bin_edges_std[0]
        cdf_std = np.cumsum(hist_std) * dx
        dx = bin_edges_ctr[1] - bin_edges_ctr[0]
        cdf_ctr = np.cumsum(hist_ctr) * dx

        # Dummy values
        cdf_ctr = np.insert(cdf_ctr, 0, 0)
        cdf_std = np.insert(cdf_std, 0, 0)
        bin_edges_ctr = [0] + bin_edges_ctr
        bin_edges_std = [0] + bin_edges_std

        ax.plot(bin_edges_std, cdf_std, label="Standard", color="red", linestyle="-")
        ax.plot(bin_edges_ctr, cdf_ctr, label="Controller", color="darkblue", linestyle="-.")
        if jitter:
            ax.set_xlabel("Jitter [ms]")
        else:
            ax.set_xlabel("Loss during the benchmark [%]")
        ax.set_ylabel("ECDF")
        plt.legend(loc="best")
        if jitter:
            plt.savefig("figures/exp_controller_udp_jitter_cdf.svg")
        else:
            plt.savefig("figures/exp_controller_udp_loss_cdf.pgf")
        # plt.show()
    else:
        k_idx = [99, 96, 93, 90]
        d_idx = np.arange(0, 51, 2)
        tp_str = ["k=" + str(i) for i in k_idx]
        linestyles = ["-", "--", "-.", ":"]
        colors_std = ["lightcoral", "red", "firebrick", "darkred"]
        colors_ctr = ["slategrey", "darkcyan", "royalblue", "darkblue"]
        p_std = []  # Legend link
        p_ctr = []

        for i, k in enumerate(loss_std_by_k):
            p, = ax.plot(d_idx, k, linestyle=linestyles[i], color=colors_std[i])
            p_std.append(p)
        for i, k  in enumerate(loss_ctr_by_k):
            p, = ax.plot(d_idx, k, linestyle=linestyles[i], color=colors_ctr[i])
            p_ctr.append(p)
        
        ax.plot([0, 50], [baseline] * 2, linestyle=":", color="black")

        # Dummy plot
        p5, = plt.plot([0], marker='None',
            linestyle='None', label='dummy-tophead')

        ax.set_xlabel("Value of the 'd' parameter of the Markov dropper model")
        if jitter:
            ax.set_ylabel("Jitter [ms]")
        else:    
            ax.set_ylabel("Loss during the benchmark [%]")
        # plt.legend(ncol=2,handleheight=2.4, labelspacing=0.05)
        leg3 = plt.legend([p5] + p_std + [p5] + p_ctr,
                ["Standard"] + tp_str + ["Controller"] + tp_str,
                loc=2, ncol=2) # Two columns, vertical group labels
        if jitter:
            plt.savefig("figures/exp_controller_udp_jitter.svg")
        else:
            plt.savefig("figures/exp_controller_udp_loss.svg")
        plt.show()


def scrap_bytes_from_controller(filename):
    with open(filename, "r") as fd:
        lines = fd.readlines()
    
    median_results = []

    counter = 0
    local_res = []
    for line in lines:
        if line.split()[-3] == "Total":
            if int(line.split()[-1]) >= 1000000:
                local_res.append(int(line.split()[-1]))
            counter += 1
        if counter == 3:
            median_results.append(np.median(local_res))
            local_res = []
            counter = 0
    return median_results


def controller_udp_bytes(cdf=False):
    # Total received. Packets: 2063, Bytes: 4607946
    baseline = 4607946
    standard = scrap_bytes_from_controller("results_18_05/standard_droper_output.txt")
    controller = scrap_bytes_from_controller("results_18_05/controller_droper_output.txt")
    print(standard)
    print("---")
    print(controller)

    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)

    if cdf:
        std_normalized = [(i / baseline) * 100 for i in standard]
        ctr_normalized = [(i / baseline) * 100 for i in controller]
        min_r = min(min(std_normalized), min(ctr_normalized)) - 1
        max_r = max(max(std_normalized), max(ctr_normalized)) + 1

        hist_without, bin_edges_without = np.histogram(std_normalized, bins=60, range=(100, 300), density=True)
        hist_with, bin_edges_with = np.histogram(ctr_normalized, bins=60, range=(100, 300), density=True)
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
        ax.plot([100, 100], [0, 1], color="black", linestyle=":", label="Baseline UDP", linewidth=3)

        ax.plot(bin_edges_without[1:], cdf_without_filtered, label="Standard", color="red", linestyle="-")
        ax.plot(bin_edges_with[1:], cdf_rfc_filtered, label="Controller", color="darkblue", linestyle="-.")

        ax.set_xlabel("Bytes sent compared to the UDP baseline (i.e. without loss) [%]")
        ax.set_ylabel("ECDF")
        plt.legend()
        plt.ylim((0, 1))

        # plt.title("Data sent by the MQTT clients (+ the UDP traffic)\nDepending on k and d from the Markov loss model")
        # plt.ylim((min_r, max_r))
        # plt.savefig("figures/udp_controller_bytes.pgf")
        plt.savefig("figures/udp_controller_bytes.pdf")
        print("fig saved")
        plt.show()


def analyze_apache_benchmark_csv():
    dir_without = "ab_27_05/without/csv"
    dir_rlc_4_2 = "ab_27_05/rlc_4_2/csv"

    _, _, filenames_std = next(os.walk(dir_without))
    _, _, filenames_ctr = next(os.walk(dir_rlc_4_2))

    sorted_filenames_std = sorted(filenames_std, key=sort_list_by_idx)
    sorted_filenames_ctr = sorted(filenames_ctr, key=sort_list_by_idx)

    loss_std = []
    loss_ctr = []
    
    for filename in tqdm(sorted_filenames_std):
        data = pd.read_csv(os.path.join(dir_without, filename))
        x = data.values[:, 0]
        y = data.values[:, 1]
        plt.plot(y, x, color="red")
    
    for filename in tqdm(sorted_filenames_ctr):
        data = pd.read_csv(os.path.join(dir_rlc_4_2, filename))
        x = data.values[:, 0]
        y = data.values[:, 1]
        plt.plot(y, x, color="darkblue", linestyle=":")
    
    # plt.xlim((0, 500))

    plt.show()


def scrap_ab_per_file(filename, percentile=False):
    with open(filename, "r") as fd:
        lines = fd.readlines()
    for line in lines:
        tab = line.split()
        if percentile:
            if len(tab) < 2: continue
            if tab[0] == "80%": return float(tab[1])
        else:
            if len(tab) < 4: continue
            if tab[0] == "Time" and tab[2] == "request:":
                return float(tab[3])


def scrap_ab_big(filename, percentile=False):
    total = []
    with open(filename, "r") as fd:
        lines = fd.readlines()
    for line in lines:
        tab = line.split()
        if percentile:
            if len(tab) < 2: continue
            if tab[0] == "80%": total.append(float(tab[1]))
        else:
            if len(tab) < 4: continue
            if tab[0] == "Time" and tab[2] == "request:" and float(tab[3]) > 50:
                total.append(float(tab[3]))
    return total


def analyze_apache_benchmark_scrap():
    dir_without = "ab_27_05/without/terminal"
    dir_rlc_4_2 = "ab_27_05/rlc_4_2/ab_global.txt"

    _, _, filenames_without = next(os.walk(dir_without))

    sorted_filenames_without = sorted(filenames_without, key=sort_list_by_idx)

    time_without = []
    time_rlc_4_2 = []

    mean_without = []
    mean_rlc_4_2 = []

    for filename in sorted_filenames_without:
        val = scrap_ab_per_file(os.path.join(dir_without, filename), True)
        if val is not None:
            time_without.append(val)
        val = scrap_ab_per_file(os.path.join(dir_without, filename), False)
        if val is not None:
            mean_without.append(val)
    
    time_rlc_4_2 = scrap_ab_big(dir_rlc_4_2, True)
    mean_rlc_4_2 = scrap_ab_big(dir_rlc_4_2, False)
    print(len(time_rlc_4_2), len(time_without))

    min_x = min([min(time_without), min(time_rlc_4_2)])
    max_x = max([max(time_without), max(time_rlc_4_2)])

    hist_without, bin_edges_without = np.histogram(time_without, bins=10000, range=(min(time_without), max(time_without) + 1), density=True)
    hist_rlc, bin_edges_rlc = np.histogram(time_rlc_4_2, bins=10000, range=(min(time_rlc_4_2), max(time_rlc_4_2) + 1), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    dx = bin_edges_rlc[1] - bin_edges_rlc[0]
    cdf_rlc = np.cumsum(hist_rlc) * dx

    # Mean
    hist_without_mean, bin_edges_without_mean = np.histogram(mean_without, bins=10000, range=(min(mean_without), max(mean_without) + 1), density=True)
    hist_rlc_mean, bin_edges_rlc_mean = np.histogram(mean_rlc_4_2, bins=10000, range=(min(mean_rlc_4_2), max(mean_rlc_4_2) + 1), density=True)
    dx = bin_edges_without_mean[1] - bin_edges_without_mean[0]
    cdf_without_mean = np.cumsum(hist_without_mean) * dx
    dx = bin_edges_rlc_mean[1] - bin_edges_rlc_mean[0]
    cdf_rlc_mean = np.cumsum(hist_rlc_mean) * dx

    # Dummy values
    #cdf_rlc = np.insert(cdf_rlc, 0, 0)
    #cdf_without = np.insert(cdf_without, 0, 0)
    #bin_edges_rlc = [0] + bin_edges_rlc
    #bin_edges_without = [0] + bin_edges_without

    fig, ax = plt.subplots()
    ax.grid()
    ax.set_axisbelow(True)

    wm, = ax.plot(bin_edges_without_mean[1:], cdf_without_mean, color="red", label=r"TCP")
    rm, = ax.plot(bin_edges_rlc_mean[1:], cdf_rlc_mean, color="darkblue", label=r"RLC", linestyle="-.")
    wp, = ax.plot(bin_edges_without[1:], cdf_without, color="darkgoldenrod", label=r"TCP", linestyle="--")
    rp, = ax.plot(bin_edges_rlc[1:], cdf_rlc, color="royalblue", label=r"RLC", linestyle=":")

    # Dummy plot
    p5, = plt.plot(100, 0, marker='None',
        linestyle='None', label=r'dummy-tophead')
    leg3 = plt.legend([p5] + [wm, rm] + [p5] + [wp, rp],
                [r"Mean"] + [r"TCP", r"RLC"] + [r"80%"] + [r"TCP", r"RLC"],
                loc="best", ncol=2) # Two columns, vertical group labels

    plt.ylabel(r"ECDF")
    plt.xlabel(r"Time per request [ms]")
    # plt.tight_layout()
    # plt.gca().xaxis.set_major_formatter(PercentFormatter(1))
    plt.savefig("figures/exp_ab_latency_cdf.pgf")
    # plt.show()


def read_tcp_json(filename, retr=False):
    with open(filename, "r") as fd:
        data = json.load(fd)
    res = []
    for run in data:
        if retr:
            res.append(run["end"]["sum_sent"]["retransmits"])
        else:
            res.append(run["end"]["sum_received"]["end"])
    return res


def read_tcp_txt(filename, retr=False):
    with open(filename, "r") as fd:
        lines = fd.readlines()
    res = []
    for line in lines:
        tab = line.split()
        if len(tab) > 0:
            if retr:
                if tab[-1] == "sender":
                    res.append(int(tab[-2]))
            else:
                if tab[-1] == "receiver":
                    res.append(float(tab[2].split("-")[1]))
    return res


def tcp_quality_cdf_2(retr=False):
    filename_without = "results_02_06/without.json"
    filename_rlc_8_2 = "results_02_06/rlc_8_2.json"

    res_without = read_tcp_json(filename_without, retr)
    res_rlc_8_2 = read_tcp_txt(filename_rlc_8_2, retr)
    
    # Add rest of the values assuming that they are above the max value
    without_max = max(res_without)
    if retr:
        for _ in range(len(res_without), 260): res_without.append(without_max + 10)
        hist_without, bin_edges_without = np.histogram(res_without, bins=20000, range=(min(res_without), max(res_without) + 1), density=True)
        hist_with, bin_edges_with = np.histogram(res_rlc_8_2, bins=20000, range=(min(res_rlc_8_2), max(res_rlc_8_2) + 1), density=True)
    else:
        for _ in range(len(res_without), 260): res_without.append(without_max * 1.1)
        hist_without, bin_edges_without = np.histogram(res_without, bins=20000, range=(min(res_without), max(res_without) + 1), density=True)
        hist_with, bin_edges_with = np.histogram(res_rlc_8_2, bins=20000, range=(min(res_rlc_8_2), max(res_rlc_8_2) + 1), density=True)
    dx = bin_edges_without[1] - bin_edges_without[0]
    cdf_without = np.cumsum(hist_without) * dx
    dx = bin_edges_with[1] - bin_edges_with[0]
    cdf_with = np.cumsum(hist_with) * dx

    fig, ax = plt.subplots()

    ax.grid()
    ax.set_axisbelow(True)

    ax.plot(bin_edges_without[1:], cdf_without, label="TCP", color="red", linestyle="-")
    ax.plot(bin_edges_with[1:], cdf_with, label="RLC", color="darkblue", linestyle="-.")

    if retr:
        ax.set_xlabel("Number of retransmissions")
    else:
        ax.set_xlabel("Connection time [s]")
    ax.set_ylabel("ECDF")

    plt.xlim((0, without_max))
    plt.legend()
    if retr:
        plt.savefig("figures/tcp_retr_cdf.pgf")
    else:
        plt.savefig("figures/tcp_time_cdf.pgf")
    
    # plt.show()


if __name__ == "__main__":
    # plugin_overhead_slides()
    # analyze_tpc_congestion_window_all(scrap_cw, boxplot=True)
    # analyze_udp_loss(cdf=True, boxplot=False)
    # analyze_tcp_quality()
    # tcp_quality_cdf_2(False)
    # analyze_retransmission()
    analyze_udp_traffic(cdf=True, jitter=False)
    # rlc_vs_udp()
    # analyze_controller()
    # controller_by_k()
    # analyze_controller_udp_traffic(cdf=True)  # Loss
    # controller_udp_bytes(cdf=True)
    # analyze_apache_benchmark_scrap()
    # analyze_apache_benchmark_csv()
