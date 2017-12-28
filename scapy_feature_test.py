#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 28 15:40:59 2017

@author: root
"""

# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Sep 20 16:14:48 2017

@author: root
"""
import pandas as pd
import numpy as np
import datetime
import scapy.all as scapy

ts = []  # timestampe
proto = []

src = []
dst = []
sport = []
dport = []


def scapy_pcap():
    with scapy.PcapReader('/data/ray/pcap/example_network_traffic.pcap') as pcap_reader:
        #num = 0
        for pkt in pcap_reader:
            '''
            
            #num += 1
            #if num < 100000:
            # pkt.show()
                try:
                    pkt.time
                    pkt.src
                    pkt.dst
                    pkt.sport
                    pkt.dport
                    pkt.proto
                except:
                    continue
                ts.append(str(datetime.datetime.utcfromtimestamp(pkt.time)))
                src.append(pkt.src)
                dst.append(pkt.dst)
                sport.append(pkt.sport)
                dport.append(pkt.dport)
                proto.append(pkt.proto)
            #else:
            #    break
            '''

            pkt.show()
            print(str(datetime.datetime.utcfromtimestamp(pkt.time)))
            print(pkt.src)
            print(pkt.dst)
            print(pkt.sport)
            print(pkt.dport)
            print(pkt.proto)
            print(pkt.data.IP.version)
            print(pkt.data.IP.src)
            print(pkt.data.IP.dst)

if __name__ == '__main__':
    # dpkt_pcap()
    scapy_pcap()
