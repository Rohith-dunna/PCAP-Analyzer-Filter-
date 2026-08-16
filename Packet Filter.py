from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS
import os


# ---------------------------------------------------------
# Display packet information
# ---------------------------------------------------------

def display_packets(packets):

    if not packets:
        print("\nNo packets matched the filter.")
        return

    print("\n" + "=" * 90)
    print(f"{'No.':<5} {'Source':<22} {'Destination':<22} {'Protocol':<10}")
    print("=" * 90)

    for i, packet in enumerate(packets, start=1):

        # IPv4
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

        # IPv6
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst

        else:
            src = "N/A"
            dst = "N/A"

        # Protocol
        if DNS in packet:
            protocol = "DNS"

        elif TCP in packet:
            protocol = "TCP"

        elif UDP in packet:
            protocol = "UDP"

        elif ICMP in packet:
            protocol = "ICMP"

        else:
            protocol = packet.lastlayer().name

        print(f"{i:<5} {src:<22} {dst:<22} {protocol:<10}")

    print("=" * 90)
    print(f"Total packets: {len(packets)}")


# ---------------------------------------------------------
# Get IP address
# ---------------------------------------------------------

def get_ip(packet):

    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return None, None


# ---------------------------------------------------------
# Filtering functions
# ---------------------------------------------------------

def filter_source_ip(packets, ip):

    return [
        packet for packet in packets
        if get_ip(packet)[0] == ip
    ]


def filter_destination_ip(packets, ip):

    return [
        packet for packet in packets
        if get_ip(packet)[1] == ip
    ]


def filter_ip(packets, ip):

    return [
        packet for packet in packets
        if ip in get_ip(packet)
    ]


def filter_protocol(packets, protocol):

    protocol = protocol.upper()

    if protocol == "TCP":
        return [p for p in packets if TCP in p]

    elif protocol == "UDP":
        return [p for p in packets if UDP in p]

    elif protocol == "ICMP":
        return [p for p in packets if ICMP in p]

    elif protocol == "DNS":
        return [p for p in packets if DNS in p]

    else:
        print("Unsupported protocol.")
        return []


def filter_source_port(packets, port):

    return [
        p for p in packets
        if TCP in p and p[TCP].sport == port
        or UDP in p and p[UDP].sport == port
    ]


def filter_destination_port(packets, port):

    return [
        p for p in packets
        if TCP in p and p[TCP].dport == port
        or UDP in p and p[UDP].dport == port
    ]


def filter_port(packets, port):

    return [
        p for p in packets
        if (
            (TCP in p and (p[TCP].sport == port or p[TCP].dport == port))
            or
            (UDP in p and (p[UDP].sport == port or p[UDP].dport == port))
        )
    ]


# ---------------------------------------------------------
# Save filtered packets
# ---------------------------------------------------------

def save_packets(packets):

    filename = input("\nEnter output PCAP filename: ").strip()

    if not filename.endswith(".pcap"):
        filename += ".pcap"

    from scapy.all import wrpcap

    wrpcap(filename, packets)

    print(f"\nFiltered packets saved to: {filename}")


# ---------------------------------------------------------
# Main program
# ---------------------------------------------------------

def main():

    print("\n" + "=" * 60)
    print("          PCAP PACKET FILTER")
    print("=" * 60)

    # Get PCAP file
    pcap_file = input("\nEnter PCAP file path: ").strip()

    if not os.path.exists(pcap_file):
        print("\nError: File does not exist.")
        return

    if not pcap_file.lower().endswith((".pcap", ".pcapng")):
        print("\nError: Please provide a .pcap or .pcapng file.")
        return

    # Read packets
    print("\nReading PCAP file...")

    try:
        packets = rdpcap(pcap_file)

    except Exception as e:
        print(f"\nError reading PCAP: {e}")
        return

    print(f"Loaded {len(packets)} packets.")

    # Filter menu
    while True:

        print("\n" + "-" * 60)
        print("FILTER OPTIONS")
        print("-" * 60)

        print("1. Source IP")
        print("2. Destination IP")
        print("3. Any IP")
        print("4. Protocol")
        print("5. Source Port")
        print("6. Destination Port")
        print("7. Any Port")
        print("8. DNS packets")
        print("9. TCP packets")
        print("10. UDP packets")
        print("11. Show all packets")
        print("12. Save filtered packets")
        print("13. Exit")

        choice = input("\nSelect option: ").strip()

        # Source IP
        if choice == "1":

            ip = input("Enter source IP: ").strip()

            filtered = filter_source_ip(packets, ip)

            display_packets(filtered)

        # Destination IP
        elif choice == "2":

            ip = input("Enter destination IP: ").strip()

            filtered = filter_destination_ip(packets, ip)

            display_packets(filtered)

        # Any IP
        elif choice == "3":

            ip = input("Enter IP address: ").strip()

            filtered = filter_ip(packets, ip)

            display_packets(filtered)

        # Protocol
        elif choice == "4":

            protocol = input(
                "Enter protocol (TCP/UDP/ICMP/DNS): "
            ).strip()

            filtered = filter_protocol(packets, protocol)

            display_packets(filtered)

        # Source Port
        elif choice == "5":

            try:
                port = int(input("Enter source port: "))

                filtered = filter_source_port(packets, port)

                display_packets(filtered)

            except ValueError:
                print("Invalid port.")

        # Destination Port
        elif choice == "6":

            try:
                port = int(input("Enter destination port: "))

                filtered = filter_destination_port(packets, port)

                display_packets(filtered)

            except ValueError:
                print("Invalid port.")

        # Any Port
        elif choice == "7":

            try:
                port = int(input("Enter port: "))

                filtered = filter_port(packets, port)

                display_packets(filtered)

            except ValueError:
                print("Invalid port.")

        # DNS
        elif choice == "8":

            filtered = [p for p in packets if DNS in p]

            display_packets(filtered)

        # TCP
        elif choice == "9":

            filtered = [p for p in packets if TCP in p]

            display_packets(filtered)

        # UDP
        elif choice == "10":

            filtered = [p for p in packets if UDP in p]

            display_packets(filtered)

        # Show all
        elif choice == "11":

            display_packets(packets)

        # Save
        elif choice == "12":

            save_packets(packets)

        # Exit
        elif choice == "13":

            print("\nExiting...")
            break

        else:

            print("\nInvalid option.")



if __name__ == "__main__":
    main()