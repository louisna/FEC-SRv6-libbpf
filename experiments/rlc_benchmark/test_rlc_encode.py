import matplotlib.pyplot as plt
import numpy as np
import subprocess
import json
import os
import matplotlib
LATEX = False
if LATEX:
    matplotlib.use("pgf")
    matplotlib.rcParams.update({
        "pgf.texsystem": "pdflatex",
        'font.family': 'serif',
        'text.usetex': True,
        'pgf.rcfonts': False,
    })
    font_size = 14
    params = {
        'axes.labelsize': font_size, # fontsize for x and y labels (was 10)
        'axes.titlesize': font_size,
        #'text.fontsize': 11, # was 10
        'legend.fontsize': font_size, # was 10
        'xtick.labelsize': font_size,
        'ytick.labelsize': font_size,
    }
    plt.rcParams.update(params)


def rlc_encode_benchmark(size):
    window_sizes = np.arange(4, 16)
    results = []
    for ws in window_sizes:
        result = subprocess.run(["./rlc_encode", f"{ws}", "2", "6000"], stdout=subprocess.PIPE)
        j = json.loads(result.stdout.decode("utf-8"))
        results.append(np.median(j))
    
    print(results)
    np.save(f"results/{size}.npy", results)


def rlc_decode_benchmark(size):
    window_sizes = np.arange(4, 16)
    results = []
    for ws in window_sizes:
        result = subprocess.run(["./rlc_decode", f"{ws}", "2", "4000", "1"], stdout=subprocess.PIPE)
        j = json.loads(result.stdout.decode("utf-8"))
        results.append(np.median(j))
    print(results)
    np.save(f"rlc_decode_1_lost_1_check/{size}.npy", results)


def rlc_recode_benchmark_by_nb_loss():
    size = 1024
    results = []
    for loss in range(1, 35):
        result = subprocess.run(["./rlc_decode", "10", "2", "4000", f"{loss}"], stdout=subprocess.PIPE)
        j = json.loads(result.stdout.decode("utf-8"))
        results.append(np.median(j))
        print(np.median(j))
    np.save(f"results_per_packet_loss.npy", results)

def plot_rlc_encode():
    _, _, filenames = next(os.walk("results"))

    sorted_filenames = sorted(filenames, key=lambda f: int(f.split(".")[0]))

    names = []
    datas = []

    for file in sorted_filenames:
        data = np.load(os.path.join("results", file))
        datas.append(data)
        names.append(file.split(".")[0])
    
    fig, ax = plt.subplots()
    ax.grid(True, ls="-", which="both")
    ax.set_axisbelow(True)

    markers = [".", "^", "s", "x"]
    colors = ["green", "red", "darkorange", "darkblue"]
    linestyles = ["-", "-.", "--", (0, (3, 1, 1, 1))]
    i = 0
    idx_x = np.arange(4, 16)

    p_plot = []
    for name, data in zip(reversed(names), reversed(datas)):
        p, = ax.plot(idx_x, np.array(data) * 1000, label=name, color=colors[i], marker=markers[i], linestyle=linestyles[i])
        p_plot.append(p)
        i += 1
    
    p5, = plt.plot([10], [0.0002], marker='None', linestyle="None", label='dummy_tophead')
    leg3 = plt.legend([p5] + p_plot[:2] + [p5] + p_plot[2:], ["Max packet size (bytes)"] + [str(i) for i in [65536, 4098]] + [""] + [str(i) for i in [1024, 512]], loc="best", ncol=2)

    ax.set_xlabel("Window size")
    ax.set_ylabel("Time elapsed [ms]")
    # plt.yscale("log")
    plt.ylim((0.003, 1))
    # plt.savefig("rlc_encode_bm.pgf")
    plt.show()


def plot_rlc_decode():
    _, _, filenames = next(os.walk("results_decode_1_lost"))

    sorted_filenames = sorted(filenames, key=lambda f: int(f.split(".")[0]))

    names = []
    datas = []

    for file in sorted_filenames:
        data = np.load(os.path.join("results_decode_1_lost", file))
        datas.append(data)
        names.append(file.split(".")[0])
    
    fig, ax = plt.subplots()
    ax.grid(True, ls="-", which="both")
    ax.set_axisbelow(True)

    markers = [".", "^", "s", "x"]
    colors = ["green", "red", "darkorange", "darkblue"]
    linestyles = ["-", "-.", "--", (0, (3, 1, 1, 1))]
    i = 0
    idx_x = np.arange(4, 16)

    p_plot = []
    for name, data in zip(reversed(names), reversed(datas)):
        p, = ax.plot(idx_x, np.array(data) * 1000, label=name, color=colors[i], marker=markers[i], linestyle=linestyles[i])
        p_plot.append(p)
        i += 1
    
    p5, = plt.plot([10], [0.0002], marker='None', linestyle="None", label='dummy_tophead')
    leg3 = plt.legend([p5] + p_plot[:2] + [p5] + p_plot[2:], ["Max packet size (bytes)"] + [str(i) for i in [65536, 4098]] + [""] + [str(i) for i in [1024, 512]], loc="best", ncol=2)

    ax.set_xlabel("Window size")
    ax.set_ylabel("Time elapsed [ms]")
    plt.yscale("log")
    plt.ylim((0.003, 100))
    plt.savefig("rlc_decode_bm.pgf")
    # plt.show()


def plot_rlc_decode_loss():
    res = np.load("results_per_packet_loss.npy")
    fig, ax = plt.subplots()

    plt.grid()
    ax.set_axisbelow(True)
    ax.set_xlabel("Number of losses to recover")
    ax.set_ylabel("Time elapsed [ms]")
    plt.plot(np.array(res) * 1000, color="darkblue")
    plt.savefig("rlc_decode_losses.pgf")
    #plt.show()


if __name__ == "__main__":
    #rlc_encode_benchmark(65536)
    plot_rlc_encode()
    # rlc_decode_benchmark(65536)
    #plot_rlc_decode()
    # rlc_recode_benchmark_by_nb_loss()
    # plot_rlc_decode_loss()