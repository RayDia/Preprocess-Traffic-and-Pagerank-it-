
import pandas as pd
import numpy as np
import dpkt
import datetime
import socket

from dpkt.compat import compat_ord

time = []  # timestampe
ftime =[]
proto = []

src = []
dst = []
ipsrc = []
ipdst = []
sport = []
dport = []
psize = []
intipscr = []
intipdst = []
ip2int = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def dpkt_pcap():
    #dir(dpkt)
    #f = open('/data/ray/pcap/localhost-170918-00001852.pcap', 'rb')
    f = open('/data/ray/pcap/example_network_traffic.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)

    # num = 0
    for ts, buf in pcap:
        print(buf)
        print(len(buf))

if __name__ == '__main__':
    dpkt_pcap()
