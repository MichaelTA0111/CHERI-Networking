#!/usr/local64/bin/bash

# Usage: ./time_program.sh {build_dir_name} {packet_stream} {opts}

build_dir_name=$1
packet_stream=$2
opts=$3

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

# Get the packet stream directory
stream_dir=$(readlink -f "$script_dir/../packet_streams")

# Check if the packet stream exists
if [ ! -f "$stream_dir/$packet_stream" ]; then
    printf "ERROR!\nPacket stream '%s' not found!\n" "$stream_dir/$packet_stream" 1>&2
    exit 3
fi

# Check if any of the options are invalid
VALID_OPTIONS="n s i x y q v "
for (( i=0; i<${#opts}; i++ )); do
    current_opt="${opts:$i:1}"
    [[ "$VALID_OPTIONS" =~ (^|[[:space:]])"$current_opt"($|[[:space:]]) ]]
    if [[ $? != 0 ]]; then
        printf "ERROR!\nInvalid option '%s' specified. The valid options are:\n%s\n" "$current_opt" "$VALID_OPTIONS" 1>&2
        exit 4
    fi
done

time ("$build_dir"/examples/dpdk-cheri_networking -l 0 -n 4 --no-huge --no-shconf --vdev=net_pcap0,rx_pcap=packet_streams/"$packet_stream",tx_pcap=packet_streams/out.pcap -- -"$opts" &> /dev/null)
