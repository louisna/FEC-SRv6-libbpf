import os
import signal


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
print('Press Ctrl+C')


output_dir_template = lambda: f"mqtt_topo/results_without/mqtt_res_run_{i}.json"
mqtt_bench_template = f"/home/vagrant/go/bin/mqtt-benchmark --broker tcp://[2042:cc::1]:1883 --clients 3 --count 200 --format json"

for i in range(1000):
    # input(f"Press enter to launch next test with values: k={k} d={d}")
    output_dir = output_dir_template()
    command = f"{mqtt_bench_template} >> {output_dir}"
    os.system(command)
