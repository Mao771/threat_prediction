# import pcapy
# from impacket.ImpactDecoder import *
#
# # list all the network devices
# pcapy.findalldevs()
#
# max_bytes = 1024
# promiscuous = False
# read_timeout = 100 # in milliseconds
# pc = pcapy.open_live("name of network device to capture from", max_bytes,
#     promiscuous, read_timeout)
#
# pc.setfilter('tcp')
#
# # callback for received packets
# def recv_pkts(hdr, data):
#     packet = EthDecoder().decode(data)
#     print(packet)
#
# packet_limit = -1 # infinite
# pc.loop(packet_limit, recv_pkts) # capture packets

from scapy.all import *
from scapy.layers.inet import *
from threading import Timer
from definitions import ROOT_DIR


def process_packetlist(packetlist):
    tcp_in, tcp_out, udp_in, udp_out, icmp_in, icmp_out = 0, 0, 0, 0, 0, 0

    for packet in packetlist:
        if IP in packet:
            ip_layer = packet[IP]
            in_packet = ip_layer.src != '192.168.0.105'
            if TCP in packet:
                if in_packet:
                    tcp_in += 1
                else:
                    tcp_out += 1
            elif UDP in packet:
                if in_packet:
                    udp_in += 1
                else:
                    udp_out += 1
            elif ICMP in packet:
                if in_packet:
                    icmp_in += 1
                else:
                    icmp_out += 1

    write_log((tcp_in, tcp_out, udp_in, udp_out, icmp_in, icmp_out,))


def sniff(sniffer):
    try:
        sniffer.stop()
        process_packetlist(sniffer.results)
    except Exception as e:
        print(e)

    sniffer.start()
    Timer(5, sniff, [sniffer]).start()


def write_log(values):
    timestamp = time.time()
    line = ','.join([str(v) for v in values])
    filename = os.path.join(ROOT_DIR, 'parser.log')

    try:
        if os.path.getsize(filename) > 1024:
            os.remove(filename)
    except:
        pass

    with open(filename, 'a+') as f:
        f.writelines('[{}]: {}\n'.format(str(timestamp), line))


if __name__ == '__main__':
    sniff(AsyncSniffer())
