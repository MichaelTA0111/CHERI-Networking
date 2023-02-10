import os
import sys
import subprocess

import psutil


def get_packet_stream(packet_size, packet_count, consumer_count):
    return f'{packet_size:_}B__{packet_count:_}P__{consumer_count}C'


def main(build_dir_name, packet_size, packet_count, consumer_count, options,
         variable=None):
    # Construct the packet stream
    stream = get_packet_stream(packet_size, packet_count, consumer_count)
    stream_file = f'{stream}.pcap'

    # Get the script directory
    script_dir = os.path.dirname(os.path.realpath(__file__))

    # Record the CPU usage while running the program
    psutil.cpu_percent(interval=None, percpu=False)
    result = subprocess.run([f'{script_dir}/time_program.sh', build_dir_name,
                             stream_file, options],
                            capture_output=True)
    usage = psutil.cpu_percent(interval=None, percpu=False)

    # Parse the script output
    output = str(result.stdout)
    output = output.split('\\n')

    # Calculate the average packet latency
    total_latency = output[-4]
    total_latency = total_latency.split(' ')[-1]
    total_latency = int(total_latency)
    avg_latency = total_latency / packet_count

    # Print the consumer counters to the console
    consumers = output[-3:-1]
    print(f'{consumers[0]}\n{consumers[1]}')

    # Parse the execution time
    time = str(result.stderr)
    time = time.split('\\n')
    real_time = time[-3]
    real_time = real_time.split('\\t')[1]

    # Determine the results directory
    results_dir = f'{script_dir}/../results'

    if variable is not None:
        results_dir += f'/{variable}'
    else:
        results_dir += '/none'

    if 'n' in options:
        results_dir += '/none'
    elif 's' in options:
        results_dir += '/cheri'
    elif 'i' in options:
        results_dir += '/ipc'

    results_dir = os.path.abspath(results_dir)

    # Make the results directory in case it doesn't exist already
    os.makedirs(results_dir, exist_ok=True)

    # Write the results to the associated output file
    with open(f'{results_dir}/{stream}.txt', 'a') as f:
        f.write(f'{real_time},{avg_latency:.2f},{usage}\n')


if __name__ == '__main__':
    # From /home/Michael/documents/projects/DPDK-v20-11-1/morello-cheri/examples
    # Usage: python3 ~/scripts/record_metrics.py {build_dir_name} {packet_size} {packet_count} {consumer_count} {options} {variable}
    if len(sys.argv) == 6:
        main(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
    elif len(sys.argv) == 7:
        main(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6])

