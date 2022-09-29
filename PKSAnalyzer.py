from binascii import hexlify
from os.path import exists

import yaml
from scapy.all import *


# overenie filu a nasledne otvorenie cez scapy
def get_file():
    print(f"Cesta k suboru by mala vyzerat nasledovne: D:\\Python projects\pks22\\vzorky_pcap_na_analyzu\\eth-1.pcap ",
          end='\n')
    # file = str(input())
    file = "D:\\Python projects\pks22\\vzorky_pcap_na_analyzu\\eth-1.pcap"
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
def frame_data(frame, begin, end):
    return hexlify(frame[begin:(end + 1)])


def get_frame_length(frame):
    output = len(frame)
    if len(frame) + 4 > 64:
        output_m = len(frame) + 4
    else:
        output_m = 64
    return output, output_m


def get_header_length(frame):
    header_size = int(str(frame_data(frame, 14, 14))[3:-1]) * 4

    return frame[14 + header_size:len(frame)]


# vypisanie celeho framu v hexa tvare
def print_frame_hex(frame):
    output = ''
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
    return "" + frame[2:4] + ':' + frame[4:6] + ':' + frame[6:8] + ':' + frame[8:10] + ':' + frame[10:12] + ':' + frame[
                                                                                                                  12:14]


def get_mac(frame):
    # 0-5 dst add 6-11 src add
    dst_mac = extract_mac(str(frame_data(frame, 0, 5)))
    src_mac = extract_mac(str(frame_data(frame, 6, 11)))
    return src_mac.upper(), dst_mac.upper()


def extract_ip(frame):
    return "" + str(int(frame[2:4], 16)) + '.' + str(int(frame[4:6], 16)) + '.' + str(int(frame[6:8], 16)) + '.' + str(
        int(frame[8:10], 16))


def get_ip_add(frame):
    # 26-29 src ip add 30-33 dst ip add
    src_ip = extract_ip(str(frame_data(frame, 26, 29)))
    dst_ip = extract_ip(str(frame_data(frame, 30, 33)))

    return src_ip, dst_ip


def frame_type(frame):
    ether_type = int(frame_data(frame, 12, 13), 16)
    ieee_type = int(frame_data(frame, 14, 15), 16)

    if ether_type >= 1500:
        return "Ethernet 2"
    elif ieee_type == 0xAAAA:
        return "IEEE 802.3 LLC + SNAP"
    elif ieee_type == 0xFFFF:
        return "IEEE 802.3 raw"
    else:
        return "IEEE 802.3 LLC"


def inside_protocol(frame, yaml_dic):
    ether_type = int(frame_data(frame, 12, 13), 16)
    ieee_type = int(frame_data(frame, 14, 15), 16)
    eth_dic = {}
    fill_dict(eth_dic, "Protocols\\eth_typ.txt")
    ip_head = {}
    fill_dict(ip_head, "Protocols\\ip_protoly.txt")
    llc = {}
    fill_dict(llc, "Protocols\\llc_typ.txt")
    ports = {}

    if ether_type >= 1500:
        if ether_type in eth_dic:
            yaml_dic['ether_type'] = eth_dic.get(ether_type)

        else:
            print(f"Neznamy port")

        if int(frame_data(frame, 23, 23), 16) == 17:
            fill_dict(ports, "Protocols\\udp.txt")

        if int(frame_data(frame, 23, 23), 16) == 6:
            fill_dict(ports, "Protocols\\tcp.txt")


# Source: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data/15423007#15423007
def str_presenter(dumper, frame):
    if len(frame.splitlines()) > 1:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', frame, style="|")

    return dumper.represent_scalar('tag:yaml.org,2002:str', frame)


yaml.add_representer(str, str_presenter)

global_yaml = []

def yaml_out(frame, frame_num):
    output = str("")
    output += f"frame_number: {frame_num}\n"
    length, media = get_frame_length(frame)

    frame_t = frame_type(frame)
    src_mac, dst_mac = get_mac(frame)
    src_ip, dst_ip = get_ip_add(frame)
    output += f"src_mac: {src_mac}\ndst_mac: {dst_mac}\n"
    output += f"src_ip: {src_ip}\ndst_ip: {dst_ip}\n"

    yaml = {}
    yaml["frame_number"] = frame_num
    yaml['len_frame_pcap'] = length
    yaml['len_frame_medium'] = media
    yaml['frame_type'] = frame_t
    yaml['src_mac'] = src_mac
    yaml['dst_mac'] = dst_mac

    inside_protocol(frame, yaml)
    yaml['hexa_frame'] = print_frame_hex(frame)
    global_yaml.append(yaml)


def ipv4_nodes(frame, nodes):
    src_ip = str(frame_data(frame, 26, 29))

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


# parsovanie na bytes z povodneho filu
def parse_packet(data):
    ip_nodes = {}

    for frame_num, values in enumerate(data):
        frame = bytes(values)

        yaml_out(frame, frame_num + 1)

        if int(frame_data(frame, 12, 13), 16) == 2048:
            ipv4_nodes(frame, ip_nodes)
    nodes, max_sent = print_ipv4_nodes(ip_nodes)
    packets = {'packets': global_yaml,
               'ipv4_senders': nodes,
               'max_send_packets_by':max_sent,
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

parse_packet(data)
