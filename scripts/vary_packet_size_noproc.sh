#!/usr/local64/bin/bash

build_dir_name=$1

# Get the script and parent DPDK directories
script_dir="$(dirname "${BASH_SOURCE[0]}")"
parent_dir=$(readlink -f "$script_dir/../../..")

# Check if the build_dir exists
build_dir=$"$parent_dir/$build_dir_name"
if [ ! -d "$build_dir" ]; then
    printf "ERROR!\nBuild directory '%s' not found!\n" "$build_dir" 1>&2
    exit 1
elif [ ! -f "$build_dir/examples/dpdk-cheri_networking" ]; then
    printf "ERROR!\nIncomplete build directory '%s', cheri-networking has not been compiled!\nHas the ninja build been completed?\n" "$build_dir" 1>&2
    exit 2
fi

# Iterate through all available packet sizes
for PACKET_SIZE in '512' '1_024' '2_048' '4_096' '8_192'
do
    # Repeat all results 5 times for reliability
    for i in {1..5}
    do
        python3 "$script_dir"/record_metrics.py $build_dir_name $PACKET_SIZE '100_000' 2 nq packet_size
        sleep 1
    done
done
