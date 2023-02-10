#!/usr/local64/bin/bash

# Usage: ./run.sh {build_dir} {packet_stream} {opts}

build_dir=$1
packet_stream=$2
opts=$3

# cd into the built examples directory
script_dir="$(dirname "${BASH_SOURCE[0]}")"
cd "$script_dir"/../../..
cd "$build_dir"
cd examples

./dpdk-cheri_networking -l 0 -n 4 --no-huge --no-shconf --vdev=net_pcap0,rx_pcap=packet_streams/"$packet_stream",tx_pcap=packet_streams/out.pcap -- -"$opts"
