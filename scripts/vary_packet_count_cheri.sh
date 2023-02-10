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

# Iterate through all available packet counts
for PACKET_COUNT in '20_000' '40_000' '60_000' '80_000' '100_000' '120_000' '140_000' '160_000' '180_000' '200_000'
do
    # Repeat all results 5 times for reliability
    for i in {1..5}
    do
        python3 "$script_dir"/record_metrics.py $build_dir_name '512' $PACKET_COUNT 2 sq packet_count
        sleep 1
    done
done
