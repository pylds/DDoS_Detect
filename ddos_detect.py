import socket
import struct
import sys
import logging

logging.basicConfig(filename='ddos_detection.log', level=logging.INFO)

def open_socket(interface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
        logging.info(f'Socket created. Listening for traffic on interface {interface}')
        return s
    except socket.error as msg:
        logging.error(f'Socket could not be created. Error Code : {msg[0]} Message {msg[1]}')
        sys.exit()

def analyze_ip_header(ip_header):
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    protocol = iph[6]
    return protocol, iph_length

def analyze_tcp_header(tcp_header, iph_length):
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence_number = tcph[2]
    acknowledgement_number = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    return source_port, dest_port, sequence_number, acknowledgement_number, tcph_length

def analyze_traffic(interface):
    s = open_socket(interface)
    while True:
        packet = s.recvfrom(65565)
        packet = packet[0]

        ip_header = packet[14:34]
        protocol, iph_length = analyze_ip_header(ip_header)

        if protocol == 6:
            tcp_header = packet[iph_length:iph_length+20]
            source_port, dest_port, sequence_number, acknowledgement_number, tcph_length = analyze_tcp_header(tcp_header, iph_length)


def main():
    if len(sys.argv) != 2:
        print('Usage: python ddos_detection.py <interface>')
        sys.exit(1)

    interface = sys.argv[1]
    analyze_traffic(interface)

if __name__ == "__main__":
    main()
