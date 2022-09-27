from binascii import hexlify
from os.path import exists

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


# ziskanie dat z framu v danom rozsahu
def frame_data(frame, begin, end):
    return hexlify(frame[begin:(end + 1)])

#def get_header_length(frame):


def get_frame_length(frame):
    output = str("")
    output += f"len_frame_pcap: {len(frame)}\n"
    if len(frame) + 4 > 64:
        output += f"len_frame_medium:  {len(frame) + 4}\n"
    else:
        output += f"len_frame_medium: 64\n"
    return output


# vypisanie celeho framu v hexa tvare
def print_frame_hex(frame):
    output = str("")
    for index, frame_v in enumerate(frame):
        output += (str(hexlify(frame[index:(index + 1)]))[2:4] + ' ')

        if (index + 1) % 16 == 0:
            output += '\n'
            continue

        if (index + 1) % 8 == 0:
            output += ' '

    return output


final_yaml = []


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


def yaml_out(frame, frame_num):
    output = str("")
    output += f"frame_number: {frame_num}\n"
    output += get_frame_length(frame)
    src_mac,dst_mac = get_mac(frame)
    src_ip, dst_ip = get_ip_add(frame)
    output += f"src_mac: {src_mac}\ndst_mac: {dst_mac}\n"
    output += f"src_ip: {src_ip}\ndst_ip: {dst_ip}\n"
    output += f"hexa_frame: \n{print_frame_hex(frame)}"

    print(output)


# parsovanie na bytes z povodneho filu
def parse_packet(data):
    for frame_num, values in enumerate(data):
        frame = bytes(values)

        yaml_out(frame, frame_num + 1)
        break


# User interface
# loop ktory kontroluje ze zadany subor existuje
data = None
while (True):

    data, err = get_file()
    if data is not None:
        break
    print(err)

parse_packet(data)

# with open(r'output.yaml','w') as file:
#     documents = yaml.dump(final_yaml,file,default_flow_style=False)
