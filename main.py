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
    return int(hexlify(frame[begin:(end + 1)]), 16)


# vypisanie celeho framu v hexa tvare
def print_frame_hex(frame):
    for index, frame_v in enumerate(frame):
        print(str(hexlify(frame[index:(index + 1)]))[2:4], end=' ')

        if (index + 1) % 16 == 0:
            print()
            continue
        if (index + 1) % 8 == 0:
            print(' ', end='')
    print(f"\n")


# parsovanie na bytes z povodneho filu
def parse_packet(data):
    for frame_num, values in enumerate(data):
        frame = bytes(values)

        print_frame_hex(frame)


# User interface
# loop ktory kontroluje ze zadany subor existuje
data = None
while (True):

    data, err = get_file()
    if data is not None:
        break
    print(err)

parse_packet(data)
