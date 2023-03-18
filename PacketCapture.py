from scapy.all import *
import psutil, socket

interfaces = psutil.net_if_addrs()

# Print the names of the available network interfaces
for interface, addrs in interfaces.items():
    print("+", interface)

# Ask the user to choose an interface
interface = input("\nNetwork interface: ")

print("\nProtocol / Source IP:Port / Destination Host:Port / Service\n")


# Define a callback function to process each packet
def process_packet(packet):
    # Get the source and destination IP and port
    global service

    src_ip = packet[0][1].src
    src_port = packet[0][1].sport
    dst_ip = packet[0][1].dst
    dst_port = packet[0][1].dport

    # Get the protocol
    protocol = packet[0][1].proto
    if protocol == 6:
        protocol = "TCP"
    elif protocol == 17:
        protocol = "UDP"

    # Get the service name
    if dst_port == 80:
        service = "http"
    elif dst_port == 443:
        service = "https"
    else:
        try:
            if protocol == "TCP":
                service = socket.getservbyport(dst_port, "tcp")
            elif protocol == "UDP":
                service = socket.getservbyport(dst_port, "udp")
        except socket.error:
            service = "other"

    # Get the hostname of the destination IP
    try:
        dst_host = socket.gethostbyaddr(dst_ip)[0]
    except socket.herror:
        dst_host = dst_ip

    # Print the information
    print(f"\033[93m{protocol}\033[0m | \033[34m{src_ip}:{src_port}\033[0m | \033[91m{dst_host}:{dst_port}\033[0m | "
          f"\033[95m{service}\033[0m")


def sniffer():
    try:
        # Use the sniff function to start capturing packets
        sniff(iface=interface, prn=process_packet)
    except:
        sniffer()


sniffer()
