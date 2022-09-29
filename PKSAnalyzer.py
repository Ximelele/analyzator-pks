from binascii import hexlify
from os.path import exists

import yaml
from scapy.all import *


# overenie filu a nasledne otvorenie cez scapy
def get_file():
    print(f"Cesta k suboru by mala vyzerat nasledovne: D:\\Python projects\pks22\\vzorky_pcap_na_analyzu\\eth-1.pcap ",
          end='\n')
    # file = str(input())
    file = "D:\\Python projects\pks22\\vzorky_pcap_na_analyzu\\trace-14.pcap"
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
    return str() + frame[2:4] + ':' + frame[4:6] + ':' + frame[6:8] + ':' + frame[8:10] + ':' + frame[10:12] + ':' + frame[
                                                                                                                  12:14]


def get_mac(frame):
    # 0-5 dst add 6-11 src add
    dst_mac = extract_mac(str(frame_data(frame, 0, 5)))
    src_mac = extract_mac(str(frame_data(frame, 6, 11)))
    return src_mac.upper(), dst_mac.upper()


def extract_ip(frame):
    return str() + str(int(frame[2:4], 16)) + '.' + str(int(frame[4:6], 16)) + '.' + str(int(frame[6:8], 16)) + '.' + str(
        int(frame[8:10], 16))


def get_ip_add(frame,ip=True):
    # 26-29 src ip add 30-33 dst ip add
    if ip:
        src_ip = extract_ip(str(frame_data(frame, 26, 29)))
        dst_ip = extract_ip(str(frame_data(frame, 30, 33)))
    #28-31 src 38-41 dst arp ip add
    else:
        src_ip = extract_ip(str(frame_data(frame, 28, 31)))
        dst_ip = extract_ip(str(frame_data(frame, 38, 41)))
    return src_ip, dst_ip


def frame_type(frame):
    ether_type = int(frame_data(frame, 12, 13), 16)
    ieee_type = int(frame_data(frame, 14, 15), 16)

    if ether_type >= 1500:
        return "ETHERNET II"
    elif ieee_type == 0xAAAA:
        return "IEEE 802.3 LLC & SNAP"
    elif ieee_type == 0xFFFF:
        return "IEEE 802.3 RAW"
    else:
        return "IEEE 802.3 LLC"


def ports_out(frame,yaml_dic):
    yaml_dic['src_port']=int(frame_data(get_header_length(frame),0,1),16)
    yaml_dic['dst_port']=int(frame_data(get_header_length(frame),2,3),16)

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
    ip_head_num = int(frame_data(frame, 23, 23), 16)
    if ether_type >= 1500:
        if ether_type in eth_dic:
            yaml_dic['ether_type'] = eth_dic.get(ether_type)

        else:
            print(f"Neznamy port")

        if int(frame_data(frame, 23, 23), 16) == 17:
            fill_dict(ports, "Protocols\\udp.txt")

        if int(frame_data(frame, 23, 23), 16) == 6:
            fill_dict(ports, "Protocols\\tcp.txt")

        if ether_type == 2054:
            src_ip, dst_ip = get_ip_add(frame,False)
            if int(frame_data(frame,20,21),16) == 1:
                yaml_dic['arp_opcode']= str("REQUEST")
            else:
                yaml_dic['arp_opcode']= str("REPLY")
            yaml_dic['src_ip'] = src_ip
            yaml_dic['dst_ip'] = dst_ip


        if ether_type == 2048:
            src_ip, dst_ip = get_ip_add(frame)
            yaml_dic['src_ip'] = src_ip
            yaml_dic['dst_ip'] = dst_ip

            if ip_head_num in ip_head:
                yaml_dic['protocol']=ip_head.get(ip_head_num)
            ports_out(frame,yaml_dic)
            if int(frame_data(get_header_length(frame),0,1),16) in ports:
                yaml_dic['app_protocol'] = ports.get(int(frame_data(get_header_length(frame),0,1),16))
            else:
                if int(frame_data(get_header_length(frame),2,3),16) in ports:
                    yaml_dic['app_protocol'] = ports.get(int(frame_data(get_header_length(frame),2,3),16))
                else:
                    yaml_dic['app_protocol']=str("unknown")
            if ip_head_num == 1:
                icmp = {}
                fill_dict(icmp, "Protocols\\icmp_typ.txt")

                if int(frame_data(get_header_length(frame),0,0),16) in icmp:
                    yaml_dic["icmp_type"]=icmp.get(int(frame_data(get_header_length(frame),0,0),16))
    elif ieee_type == 0xAAAA:
        if ether_type in eth_dic:
            yaml_dic['sap']= eth_dic.get(ether_type)
        else:
            yaml_dic['sap']= str("Unknown")
    elif ieee_type == 0xFFFF:
        yaml_dic['sap']= str("IPX")
    elif int(frame_data(get_header_length(frame),14,14),16) in llc:
        yaml_dic['sap'] = llc.get(int(frame_data(get_header_length(frame),14,14),16))







# Source: https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data/15423007#15423007
def str_presenter(dumper, frame):
    if len(frame.splitlines()) > 1:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', frame, style="|")

    return dumper.represent_scalar('tag:yaml.org,2002:str', frame)


yaml.add_representer(str, str_presenter)

global_yaml = []


def yaml_out(frame, frame_num):
    yaml_dic = dict()
    length, media = get_frame_length(frame)
    src_mac, dst_mac = get_mac(frame)
    yaml_dic["frame_number"] = frame_num
    yaml_dic['len_frame_pcap'] = length
    yaml_dic['len_frame_medium'] = media
    yaml_dic['frame_type'] = frame_type(frame)
    yaml_dic['src_mac'] = src_mac
    yaml_dic['dst_mac'] = dst_mac

    inside_protocol(frame, yaml_dic)
    yaml_dic['hexa_frame'] = print_frame_hex(frame)
    global_yaml.append(yaml_dic)


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
    packets = {'name':"PKS2022/23",
               'pcap_name':"all.pcap",
               'packets': global_yaml,
               'ipv4_senders': nodes,
               'max_send_packets_by': max_sent,
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
