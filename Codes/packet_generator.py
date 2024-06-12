import socket
import struct
import random
import time

def create_random_mac():
    """Generates a random MAC address."""
    return bytes([random.randint(0, 255) for _ in range(6)])

def create_random_ip():
    """Generates a random IP address."""
    return bytes([random.randint(0, 255) for _ in range(4)])

def create_tcp_packet():
    """Creates a TCP packet with random fields."""
    dst_mac = create_random_mac()
    src_mac = create_random_mac()
    ethertype = b'\x08\x00'  # IPv4 ethertype

    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 20 + 20  # IP header + TCP header
    identification = random.randint(0, 65535)
    flags_offset = 0
    ttl = random.randint(64, 255)
    protocol = 6  # TCP
    checksum = 0  # Placeholder, calculated later if needed
    src_ip = create_random_ip()
    dst_ip = create_random_ip()

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum, src_ip, dst_ip)

    src_port = random.randint(1024, 65535)
    dst_port = random.randint(1024, 65535)
    seq = random.randint(0, 4294967295)
    ack = random.randint(0, 4294967295)
    data_offset_reserved_flags = (5 << 12)  # Data offset of 5 32-bit words
    flags = random.randint(0, 0x3F)  # Randomly set TCP flags
    data_offset_reserved_flags |= flags
    window = socket.htons(5840)
    checksum = 0  # Placeholder, calculated later if needed
    urgent_pointer = 0

    tcp_header = struct.pack('!HHLLHHHH', src_port, dst_port, seq, ack, data_offset_reserved_flags, window, checksum, urgent_pointer)
    packet = dst_mac + src_mac + ethertype + ip_header + tcp_header + b"Random payload data"
    return packet

def create_udp_packet():
    """Creates a UDP packet with random fields."""
    dst_mac = create_random_mac()
    src_mac = create_random_mac()
    ethertype = b'\x08\x00'  # IPv4 ethertype

    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 20 + 8  # IP header + UDP header
    identification = random.randint(0, 65535)
    flags_offset = 0
    ttl = random.randint(64, 255)
    protocol = 17  # UDP
    checksum = 0  # Placeholder, calculated later if needed
    src_ip = create_random_ip()
    dst_ip = create_random_ip()

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum, src_ip, dst_ip)

    src_port = random.randint(1024, 65535)
    dst_port = random.randint(1024, 65535)
    length = 8 + 20  # UDP header + data length
    checksum = 0  # Placeholder, calculated later if needed

    udp_header = struct.pack('!HHHH', src_port, dst_port, length, checksum)
    packet = dst_mac + src_mac + ethertype + ip_header + udp_header + b"Random payload data"
    return packet

def create_icmp_packet():
    """Creates an ICMP packet with random fields."""
    dst_mac = create_random_mac()
    src_mac = create_random_mac()
    ethertype = b'\x08\x00'  # IPv4 ethertype

    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 20 + 8  # IP header + ICMP header
    identification = random.randint(0, 65535)
    flags_offset = 0
    ttl = random.randint(64, 255)
    protocol = 1  # ICMP
    checksum = 0  # Placeholder, calculated later if needed
    src_ip = create_random_ip()
    dst_ip = create_random_ip()

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum, src_ip, dst_ip)

    icmp_type = 8  # Echo request
    code = 0
    checksum = 0  # Placeholder, calculated later if needed
    identifier = random.randint(0, 65535)
    sequence_number = random.randint(0, 65535)

    icmp_header = struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence_number)
    packet = dst_mac + src_mac + ethertype + ip_header + icmp_header + b"Random payload data"
    return packet

def send_random_packets():
    """Sends multiple TCP, UDP, or ICMP packets with random fields and flags, with a delay between each packet."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind(('eth0', 0))  # Replace 'eth0' with the appropriate network interface for your system

    try:
        while True:
            packet_type = random.choice(['tcp', 'udp', 'icmp'])
            if packet_type == 'tcp':
                packet = create_tcp_packet()
            elif packet_type == 'udp':
                packet = create_udp_packet()
            else:
                packet = create_icmp_packet()
            
            s.send(packet)
            time.sleep(1)  # 1s delay
    except KeyboardInterrupt:
        print("Stopped by user. Exiting...")
    finally:
        s.close()
        print("Socket closed.")

if __name__ == "__main__":
    send_random_packets()
