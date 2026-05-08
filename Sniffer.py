import csv
import msvcrt   # Windows-only
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap

#store packets for pcap log file once q is pressed to stop the script
captured_packets = []
csv_filename = "packet_log.csv"#output file for all packets that have been sniffed and extracted the necessary data
stop_sniffer = False #bool value that will terminate the sniffer once user presses key q
#setting up the columns for the output cvs file
COLUMN_WIDTHS = {
    "Timestamp": 20,
    "Source IP": 20,
    "Destination IP": 20,
    "Protocol": 10,
    "Details": 40,
    "Payload": 50
}
#function to format the output of the csv file
def format_field(value, width):
    return str(value).ljust(width)[:width]
#function to write into the csv file, setting up the titles for each column
def write_header():
    with open(csv_filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        header = [format_field(col, COLUMN_WIDTHS[col]) for col in COLUMN_WIDTHS]
        writer.writerow(header)
#function to extract the required data from the captured packet. Then writing that information into the respective column in the csv log file
def log_packet(timestamp, src_ip, dst_ip, proto, details, payload):
    with open(csv_filename, mode="a", newline="") as file:
        writer = csv.writer(file)
        row = [
            format_field(timestamp, COLUMN_WIDTHS["Timestamp"]),
            format_field(src_ip, COLUMN_WIDTHS["Source IP"]),
            format_field(dst_ip, COLUMN_WIDTHS["Destination IP"]),
            format_field(proto, COLUMN_WIDTHS["Protocol"]),
            format_field(details, COLUMN_WIDTHS["Details"]),
            format_field(payload, COLUMN_WIDTHS["Payload"])
        ]
        writer.writerow(row)
#function to capture each packet, identify the packet information, protocol, IPs, port numbers and payload data and the details of the packet
def packet_callback(packet):
    captured_packets.append(packet)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        if TCP in packet:
            tcp_layer = packet[TCP]
            details = f"TCP {tcp_layer.sport}->{tcp_layer.dport}, Flags={tcp_layer.flags}"
        elif UDP in packet:
            udp_layer = packet[UDP]
            details = f"UDP {udp_layer.sport}->{udp_layer.dport}"
        elif ICMP in packet:
            details = "ICMP Packet"
        else:
            details = "Other IP Protocol"

        raw_payload = bytes(packet[IP].payload)
        payload = raw_payload[:50] if raw_payload else ""

        print("="*60)
        print(f"[{timestamp}] {src_ip} -> {dst_ip} | Protocol: {proto}")
        print(f"Details: {details}")
        if payload:
            print(f"Payload (raw): {payload}...")

        log_packet(timestamp, src_ip, dst_ip, proto, details, payload)

    else:
        print("="*60)
        print(f"[{timestamp}] Non-IP Packet captured")
        log_packet(timestamp, "-", "-", "-", "Non-IP Packet", "")
#function that runs the sniffer while the bool value is still set to False, calling the packet_callback function
def start_sniffer():
    global stop_sniffer
    print("Starting Network Sniffer with Aligned CSV Logging...")
    write_header()

    try:
        while not stop_sniffer:
            # sniff for 2 seconds, then return
            sniff(prn=packet_callback, store=False, timeout=2)

            # check if a key was pressed
            if msvcrt.kbhit():  # non-blocking check
                key = msvcrt.getch().decode("utf-8").lower()
                if key == 'q':
                    stop_sniffer = True

    except KeyboardInterrupt:
        stop_sniffer = True
    finally:
        wrpcap("captured_packets.pcap", captured_packets)
        print("\nPackets saved to captured_packets.pcap")
        print(f"Log saved to {csv_filename}")
        print("Sniffer stopped.")

if __name__ == "__main__":
    start_sniffer()
