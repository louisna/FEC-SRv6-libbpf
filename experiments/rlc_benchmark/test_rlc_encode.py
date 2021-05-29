import matplotlib.pyplot as plt
import numpy as np
import subprocess
import json
import os


def rlc_encode_benchmark(size):
    window_sizes = np.arange(4, 16)
    results = []
    for ws in window_sizes:
        result = subprocess.run(["./rlc_encode", f"{ws}", "2", "4000"], stdout=subprocess.PIPE)
        j = json.loads(result.stdout.decode("utf-8"))
        results.append(np.median(j))
    
    print(results)
    np.save(f"results/{size}.npy", results)


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
    colors = ["green", "red", "orange", "darkblue"]
    linestyles = ["-", "-.", "--", (0, (3, 1, 1, 1))]
    i = 0
    idx_x = np.arange(4, 16)

    p_plot = []
    for name, data in zip(names, datas):
        p, = ax.plot(idx_x, data, label=name, color=colors[i], marker=markers[i], linestyle=linestyles[i])
        p_plot.append(p)
        i += 1
    
    p5, = plt.plot([10], [0.0002], marker='None', linestyle="None", label='dummy_tophead')
    leg3 = plt.legend([p5] + p_plot, ["Max packet size"] + [str(i) for i in [512, 1024, 4098, 65536]], loc="best", ncol=1)

    ax.set_xlabel("Window size")
    ax.set_ylabel("Time elapsed [s]")
    plt.yscale("log")
    plt.savefig("rlc_encode_bm.svg")
    plt.show()


if __name__ == "__main__":
    # rlc_encode_benchmark(512)
    plot_rlc_encode()