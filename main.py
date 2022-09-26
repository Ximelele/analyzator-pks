from binascii import hexlify
from scapy.all import *
from os.path import exists


def get_file():
    print(f"Cesta k suboru by mala vyzerat nasledovne: D:\\Python projects\pks22\\vzorky_pcap_na_analyzu\\eth-1.pcap ", end='\n')
    file = str(input())

    if exists(file):
        return rdpcap(file)

    return None



while(True):
    data = get_file()
    if data is not None:
        break

    print(f"Zadal si zlu cestu k suboru",end='\n')


