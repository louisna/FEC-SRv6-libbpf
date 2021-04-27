# MQTT latency measures

This test mesures the latency of clients to connect to a mosquitto server and publish messages. We have a mosquitto server on `hC` (IPv6 address `2042:cc::1`) and three clients from `hA` (IPv6 address `2042:aa::1`) that connect to the server and try to publish messages. 

We add losses using a TC eBPF program that simulates a Markov model to create burst losses. To get the latency of the network for the MQTT clients, we use the MQTT benchmark from krylovsk (https://github.com/krylovsk/mqtt-benchmark).

To simulate true network environment, we create a simple UDP packets sender on `h1`. It sends 5 packets every 10ms to `hC`.

## Replicate TCP results (without plugin)
- Launch the topology
- On `hC`, launch a mosquitto server by typing `mosquitto`
- On `hC`, start a netcat server to listen to the UDP packets simulating the network environment: `netcat -u -l 2042:cc::1 4444 > /dev/null 2>&1`
- On `h1`, start sending packets to `hC`: `sudo -E python3 scapy_send_packets.py -n 100000 -d 2042:cc::1 -b 5`
- On `rD`, launch the eBPF TC dropper: `sudo -E python3 attach_markov.py --ips 2042:cc::1,fc00::9 --attach rD-eth0 --attach-ingress -k 99 -d 2`
- Finally on `hA`, start the benchmark (do not forget to adjust the output directory accordingly): `sudo -E python3 mqtt_topo/run_benchmark`

## Replicate RLC FEC results (with plugin)
- Launch the topology
- On `hC`, launch a mosquitto server by typing `mosquitto`
- On `hC`, start a netcat server to listen to the UDP packets simulating the network environment: `netcat -u -l 2042:cc::1 4444 > /dev/null 2>&1`
- On `h1`, start sending packets to `hC`: `sudo -E python3 scapy_send_packets.py -n 100000 -d 2042:cc::1 -b 5`
- On `rD`, launch the eBPF TC dropper: `sudo -E python3 attach_markov.py --ips 2042:cc::1,fc00::9 --attach rD-eth0 --attach-ingress -k 99 -d 2`
- On `rE`, start the eBPF-Userspace program: `sudo ../../src/encoder` and add the route to trigger the End.BPF action: `ip -6 route add fc00::a encap seg6local action End.BPF endpoint fd /sys/fs/bpf/encoder/lwt_seg6local section decode dev rE-eth0`
- On `rC`, start the eBPF-Userspace program: `sudo ../../src/decoder` and add the route to trigger the End.BPF action: `ip -6 route add fc00::9 encap seg6local action End.BPF endpoint fd /sys/fs/bpf/decoder/lwt_seg6local section decode dev rC-eth1`
- On `rA`, add an SRv6 encapsulation rule for packets belonging to `2042:cc::1`: `ip -6 route add 2042:cc::1/64 encap seg6 mode inline segs fc00::a,fc00::9 dev rA-eth0`
- Finally on `hA`, start the benchmark (do not forget to adjust the output directory accordingly): `sudo -E python3 mqtt_topo/run_benchmark`