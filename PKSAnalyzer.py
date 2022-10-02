from binascii import hexlify
from os.path import exists

import yaml
from scapy.all import *


class TcpStreams:
    dst_ip = []
    src_ip = []
    dst_port = []
    src_port = []
    frames = []

    def __init__(self, f_dst_ip, f_src_ip, f_dst_port, f_src_port, pos):
        self.dst_ip = f_dst_ip
        self.src_ip = f_src_ip
        self.dst_port = f_dst_port
        self.src_port = f_src_port
        self.frames = []
        self.frames.append(pos + 1)


# overenie filu a nasledne otvorenie cez scapy
def get_file():
    print(f"Cesta k suboru by mala vyzerat nasledovne: D:\\Python projects\pks22\\vzorky_pcap_na_analyzu\\eth-1.pcap ",
          end='\n')
    # file = str(input())
    file = "D:\\Python projects\pks22\\vzorky_pcap_na_analyzu\\trace-11.pcap"
    err = None
    if exists(file):
        if ".pcap" in file:
            return rdpcap(file), err
        else:
            err = "Nevalidna koncovka suboru"

    if err is None:
        err = "Zadal si neexistujucu cestu k suboru"

    return None, err


def fill_dict(dict, file):
    with open(file, 'r') as f:
        for line in f:
            f_data = line.split(" ", 1)
            dict[int(f_data[0], 16)] = f_data[1].rstrip()


# ziskanie dat z framu v danom rozsahu
def get_frame_data(frame, begin, end):
    return hexlify(frame[begin:(end + 1)])


def get_frame_length(frame):
    output = len(frame)
    if len(frame) + 4 > 64:
        output_m = len(frame) + 4
    else:
        output_m = 64
    return output, output_m


def get_header_length(frame):
    header_size = int(str(get_frame_data(frame, 14, 14))[3:-1], 16) * 4

    return frame[14 + header_size:len(frame)]


# vypisanie celeho framu v hexa tvare
def print_frame_hex(frame):
    output = str()
    for index, frame_v in enumerate(frame):
        output += str(hexlify(frame[index:(index + 1)]))[2:4]

        if index == 0 or index % 16 != 15 and index != len(frame) - 1:
            output += ' '

        if (index + 1) % 16 == 0:
            output += '\n'

    if len(frame) % 16 != 0:
        output += '\n'

    return output


def extract_mac(frame):
    return str() + frame[2:4] + ':' + frame[4:6] + ':' + frame[6:8] + ':' + frame[8:10] + ':' + frame[
                                                                                                10:12] + ':' + frame[
                                                                                                               12:14]


def get_mac(frame):
    # 0-5 dst add 6-11 src add
    dst_mac = extract_mac(str(get_frame_data(frame, 0, 5)))
    src_mac = extract_mac(str(get_frame_data(frame, 6, 11)))
    return src_mac.upper(), dst_mac.upper()


def extract_ip(frame):
    return str() + str(int(frame[2:4], 16)) + '.' + str(int(frame[4:6], 16)) + '.' + str(
        int(frame[6:8], 16)) + '.' + str(
        int(frame[8:10], 16))


def get_ip_add(frame, ip=True):
    # 26-29 src ip add 30-33 dst ip add
    if ip:
        src_ip = extract_ip(str(get_frame_data(frame, 26, 29)))
        dst_ip = extract_ip(str(get_frame_data(frame, 30, 33)))
    # 28-31 src 38-41 dst arp ip add
    else:
        src_ip = extract_ip(str(get_frame_data(frame, 28, 31)))
        dst_ip = extract_ip(str(get_frame_data(frame, 38, 41)))
    return src_ip, dst_ip


def get_frame_type(frame):
    ether_type = int(get_frame_data(frame, 12, 13), 16)
    ieee_type = int(get_frame_data(frame, 14, 15), 16)

    if ether_type >= 1500:
        return "ETHERNET II"
    elif ieee_type == 0xAAAA:
        return "IEEE 802.3 LLC & SNAP"
    elif ieee_type == 0xFFFF:
        return "IEEE 802.3 RAW"
    else:
        return "IEEE 802.3 LLC"


def ports_out(frame, yaml_dic):
    yaml_dic['src_port'] = int(get_frame_data(get_header_length(frame), 0, 1), 16)
    yaml_dic['dst_port'] = int(get_frame_data(get_header_length(frame), 2, 3), 16)


def inside_protocol(frame, yaml_dic):
    ether_type = int(get_frame_data(frame, 12, 13), 16)
    ieee_type = int(get_frame_data(frame, 14, 15), 16)
    eth_dic = {}
    fill_dict(eth_dic, "Protocols\\eth_typ.txt")
    ip_head = {}
    fill_dict(ip_head, "Protocols\\ip_protoly.txt")
    llc = {}
    fill_dict(llc, "Protocols\\llc_typ.txt")
    ports = {}
    ip_head_num = int(get_frame_data(frame, 23, 23), 16)
    if ether_type >= 1500:
        if ether_type in eth_dic:
            yaml_dic['ether_type'] = eth_dic.get(ether_type)

        else:
            print(f"Unknown port")

        if int(get_frame_data(frame, 23, 23), 16) == 17:
            fill_dict(ports, "Protocols\\udp.txt")

        if int(get_frame_data(frame, 23, 23), 16) == 6:
            fill_dict(ports, "Protocols\\tcp.txt")

        if ether_type == 2054:
            src_ip, dst_ip = get_ip_add(frame, False)
            if int(get_frame_data(frame, 20, 21), 16) == 1:
                yaml_dic['arp_opcode'] = str("REQUEST")
            else:
                yaml_dic['arp_opcode'] = str("REPLY")
            yaml_dic['src_ip'] = src_ip
            yaml_dic['dst_ip'] = dst_ip

        if ether_type == 2048:
            src_ip, dst_ip = get_ip_add(frame)
            yaml_dic['src_ip'] = src_ip
            yaml_dic['dst_ip'] = dst_ip

            if ip_head_num in ip_head:
                yaml_dic['protocol'] = ip_head.get(ip_head_num)
            ports_out(frame, yaml_dic)
            if int(get_frame_data(get_header_length(frame), 0, 1), 16) in ports:
                yaml_dic['app_protocol'] = ports.get(int(get_frame_data(get_header_length(frame), 0, 1), 16))
            else:
                if int(get_frame_data(get_header_length(frame), 2, 3), 16) in ports:
                    yaml_dic['app_protocol'] = ports.get(int(get_frame_data(get_header_length(frame), 2, 3), 16))
                else:
                    yaml_dic['app_protocol'] = str("unknown")
            if ip_head_num == 1:
                icmp = {}
                fill_dict(icmp, "Protocols\\icmp_typ.txt")

                if int(get_frame_data(get_header_length(frame), 0, 0), 16) in icmp:
                    yaml_dic["icmp_type"] = icmp.get(int(get_frame_data(get_header_length(frame), 0, 0), 16))
    elif ieee_type == 0xAAAA:
        if ether_type in eth_dic:
            yaml_dic['sap'] = eth_dic.get(ether_type)
        else:
            yaml_dic['sap'] = str("Unknown")
    elif ieee_type == 0xFFFF:
        yaml_dic['sap'] = str("IPX")
    elif int(get_frame_data(get_header_length(frame), 14, 14), 16) in llc:
        yaml_dic['sap'] = llc.get(int(get_frame_data(get_header_length(frame), 14, 14), 16))


# Source: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data/15423007#15423007
def str_presenter(dumper, frame):
    if len(frame.splitlines()) > 1:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', frame, style="|")

    return dumper.represent_scalar('tag:yaml.org,2002:str', frame)


yaml.add_representer(str, str_presenter)

global_yaml = []


def yaml_out(frame, frame_num, temp_dic):
    yaml_dic = dict()
    length, media = get_frame_length(frame)
    src_mac, dst_mac = get_mac(frame)
    yaml_dic["frame_number"] = frame_num
    yaml_dic['len_frame_pcap'] = length
    yaml_dic['len_frame_medium'] = media
    yaml_dic['frame_type'] = get_frame_type(frame)
    yaml_dic['src_mac'] = src_mac
    yaml_dic['dst_mac'] = dst_mac

    inside_protocol(frame, yaml_dic)
    yaml_dic['hexa_frame'] = print_frame_hex(frame)
    if temp_dic is None:
        global_yaml.append(yaml_dic)
        return
    temp_dic.append(yaml_dic)


def ipv4_nodes(frame, nodes):
    src_ip = str(get_frame_data(frame, 26, 29))

    if src_ip in nodes:
        nodes[src_ip] += 1
    else:
        nodes[src_ip] = 1


def print_ipv4_nodes(nodes):
    send = []
    max_send = max(nodes, key=lambda x: nodes[x])
    max_send = nodes[max_send]
    max_array = []

    for ip in nodes:
        if nodes[ip] == max_send:
            max_array.append(extract_ip(ip))
        ipv4_senders = {
            'node': extract_ip(ip),
            'number_of_sent_packets': nodes[ip]
        }

        send.append(ipv4_senders)

    return send, max_array


def ip_in_stream(tcp_stream, src_ip, dst_ip, src_port, dst_port):
    for pos in range(len(tcp_stream)):
        if (tcp_stream[pos].src_ip == dst_ip and tcp_stream[pos].dst_ip == src_ip and
            tcp_stream[pos].src_port == dst_port and tcp_stream[pos].dst_port == src_port) or \
                (tcp_stream[pos].src_ip == src_ip and tcp_stream[pos].dst_ip == dst_ip and
                 tcp_stream[pos].src_port == src_port and tcp_stream[pos].dst_port == dst_port):
            return pos
    return False


def insert_stream(tcp_stream, src_ip, dst_ip, src_port, dst_port, pos):
    new_stream = ip_in_stream(tcp_stream, src_ip, dst_ip, src_port, dst_port)

    if new_stream:
        tcp_stream[new_stream].frames.append(pos + 1)
    else:
        tcp_stream.append(TcpStreams(dst_ip, src_ip, dst_port, src_port, pos))


def print_stream(data, tcp_frame):
    arr = []
    for pos in range(len(tcp_frame)):
        frame = bytes(data[tcp_frame[pos] - 1])
        yaml_out(frame, tcp_frame[pos], arr)

    return arr


def get_ending(frame):
    return int(get_frame_data(get_header_length(frame), 13, 13))


def print_tcp_stream(tcp_stream, data):
    number_comm = 1
    partial_comms = False
    partial_comms_dic = None
    cmplt_comms = []

    for pos in tcp_stream:
        complete_comms = dict()
        begin_com = False
        end_com = False

        if len(pos.frames) >= 3:
            if (get_ending(bytes(data[pos.frames[0] - 1])) == 2) and (
                    get_ending(bytes(data[pos.frames[1] - 1])) == 12) and (
                    get_ending(bytes(data[pos.frames[2] - 1])) == 10):
                begin_com = True

        end1 = get_ending(bytes(data[pos.frames[len(pos.frames) - 1] - 1]))
        end2 = get_ending(bytes(data[pos.frames[len(pos.frames) - 2] - 1]))

        if len(pos.frames) - 3 < 0:
            three_way = False
        else:
            three_way = get_ending(bytes(data[pos.frames[len(pos.frames) - 3] - 1]))

        if len(pos.frames) - 4 < 0:
            four_way = False
        else:
            four_way = get_ending(bytes(data[pos.frames[len(pos.frames) - 4] - 1]))

        if end1 == 14 or end1 == 4:  # rst
            end_com = True
        else:
            if end1 == 10 and (end2 == 11 or end2 == 19) and (three_way == 11 or three_way == 19):  # threeway handshake
                end_com = True
            else:
                if end1 == 10 and (end2 == 11 or end2 == 19) and three_way == 10 and \
                        (four_way == 11 or four_way == 19):  # fourway handshake
                    end_com = True

        if begin_com and end_com:
            complete_comms['number_comm'] = number_comm
            complete_comms['src_comm'] = pos.src_ip
            complete_comms['dst_comm'] = pos.dst_ip
            complete_comms['packets'] = print_stream(data, pos.frames)
            cmplt_comms.append(complete_comms)
            number_comm += 1

        if not partial_comms:
            if begin_com or end_com:
                partial_comms = True
                partial_comms_dic = print_stream(data, pos.frames)

    return partial_comms_dic, cmplt_comms


# parsovanie na bytes z povodneho filu
def parse_packet(data, menu):
    menu_opt = ["HTTP", "HTTPS", "TELNET", "SSH", "FTP datove", "FTP riadiace"]
    if menu == "ALL":
        ip_nodes = {}

        for frame_num, values in enumerate(data):
            frame = bytes(values)

            yaml_out(frame, frame_num + 1, None)

            if int(get_frame_data(frame, 12, 13), 16) == 2048:
                ipv4_nodes(frame, ip_nodes)
        nodes, max_sent = print_ipv4_nodes(ip_nodes)
        packets = {'name': "PKS2022/23",
                   'pcap_name': "all.pcap",
                   'packets': global_yaml,
                   'ipv4_senders': nodes,
                   'max_send_packets_by': max_sent,
                   }
        with open('output1.yaml', 'w') as f:
            yaml.dump(packets, f, sort_keys=False, indent=3)
    elif menu in menu_opt:
        tcp_stream = []
        ports = {}
        fill_dict(ports, "Protocols\\tcp.txt")

        for frame_num, values in enumerate(data):
            frame = bytes(values)
            src_ip, dst_ip = get_ip_add(frame)
            src_port = int(get_frame_data(get_header_length(frame), 0, 1), 16)
            dst_port = int(get_frame_data(get_header_length(frame), 2, 3), 16)
            if src_port in ports:
                if ports.get(src_port) == menu:
                    insert_stream(tcp_stream, src_ip, dst_ip, src_port, dst_port, frame_num)
            elif dst_port in ports:
                if ports.get(dst_port) == menu:
                    insert_stream(tcp_stream, src_ip, dst_ip, src_port, dst_port, frame_num)
            else:
                continue
        partial_comms, complete_comms = print_tcp_stream(tcp_stream, data)

        packets = {'name': "PKS2022/23",
                   'pcap_name': menu + '.pcap',
                   'complete_comms': complete_comms,
                   'partial_comms': partial_comms,
                   }
        with open('output.yaml', 'w') as f:
            yaml.dump(packets, f, sort_keys=False, indent=3)


# User interface
# loop ktory kontroluje ze zadany subor existuje
data = None
while (True):

    data, err = get_file()
    if data is not None:
        break
    print(err)

parse_packet(data, "HTTP")
