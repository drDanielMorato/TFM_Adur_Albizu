import os
import json
import argparse
from scapy.all import rdpcap
from scapy.layers.inet import IP


def get_pcap_files_from_directory(directory):
    pcap_files = []

    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            if filename.lower().endswith((".pcap", ".pcapng")):
                pcap_files.append(os.path.join(root, filename))

    return sorted(pcap_files)

# def extract_ips_from_packet(packet):
#     ip_addresses = set()

#     if IP in packet:
#         src_ip = packet[IP].src
#         dst_ip = packet[IP].dst

#         # Ignore IPs starting with '192.168.137.'
#         if not src_ip.startswith('192.168.137.'):
#             ip_addresses.add(src_ip)
#         if not dst_ip.startswith('192.168.137.'):
#             ip_addresses.add(dst_ip)

#     return list(ip_addresses)

def process_pcap_files(file_paths):
    result = {}
    numberOfFiles = 0

    for file_path in file_paths:
        numberOfFiles+=1
        ip_timestamps : dict[str,float] = {}

        try:
            # Load the pcap file
            packets = rdpcap(file_path)
            # Extract unique IP addresses
            for packet in packets:
                if IP not in packet:
                    continue   

                src_ip = packet[IP].src
                timestamp = float(packet.time)
                # dst_ip = packet[IP].dst
                if not src_ip.startswith('192.168.137.'):
                    if src_ip in ip_timestamps:
                        if ip_timestamps[src_ip] > timestamp:
                            ip_timestamps[src_ip] = timestamp
                    else:
                        ip_timestamps[src_ip] = timestamp
                    
                    # ip_addresses.extend(extract_ips_from_packet(packet))

        except Exception as e:
            print(f"Error processing {file_path}: {e}")

        # Convert set to list before saving to JSON

        result[file_path] = ip_timestamps
        # print(result)
        # print("FILE DONE!", file_path)
    print(f"{numberOfFiles} printed")

    return result

def save_to_json(data, output_file):
    with open(output_file, 'w') as json_file:
        json.dump(data, json_file, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process PCAP files from a directory and generate ground truth JSON."
    )
    parser.add_argument(
        "directory",
        help="Directory that contains .pcap/.pcapng files (search is recursive)."
    )
    parser.add_argument(
        "--output",
        default="output.json",
        help="Output JSON file path (default: output.json)."
    )

    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        raise ValueError(f"Directory does not exist: {args.directory}")

    files = get_pcap_files_from_directory(args.directory)
    if not files:
        raise ValueError(f"No .pcap or .pcapng files found in: {args.directory}")

    result_data = process_pcap_files(files)
    save_to_json(result_data, args.output)
    # print(f"Results saved to {args.output}")
