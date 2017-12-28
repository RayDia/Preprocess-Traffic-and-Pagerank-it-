# multi pcaps

#this version is remove duplicate packets
import pandas as pd
import numpy as np
import dpkt
import datetime
import socket
import time
import os

from dpkt.compat import compat_ord

src = []
dst = []
ipsrc = []
ipdst = []
sport = []
dport = []
difpackets = []
difdictp = {}
packetsize = []

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
    #f = open('/data/ray/pcap/example_network_traffic.pcap', 'rb')
    pcapDir = '/data/ray/pcap/171026/'
    filesPath = os.listdir(pcapDir)
    for filePath in filesPath:
        sourcefile = os.path.join(pcapDir, filePath)
        file = open(sourcefile, "rb")
        pcap = dpkt.pcap.Reader(file)
    #pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:

            eth = dpkt.ethernet.Ethernet(buf)

            ip = eth.data

            try:
                socket.inet_ntoa(ip.src)
                socket.inet_ntoa(ip.dst)
            except:
                continue
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                #tcp flags
                #_fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                _syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                #_rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
                #_psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
                _ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
                #_urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0
                #_ece_flag = (tcp.flags & dpkt.tcp.TH_ECE) != 0
                #_cwr_flag = (tcp.flags & dpkt.tcp.TH_CWR) != 0

                _tempsport = tcp.sport
                _tempdport = tcp.dport

                _temppacket = socket.inet_ntoa(ip.src) + socket.inet_ntoa(ip.dst) + str(_tempsport) + str(
                    _tempdport)
                # create tcp connect
                # soulution 1
                # add to difdictp
                #solution 2
                # if _temppacket in difdictp add len
                # else _temppacket add to difdictp
                if _syn_flag == 1 & _ack_flag == 0:
                    #solution 2
                    if _temppacket in difdictp:
                        difdictp[_temppacket] += len(buf)
                    else:
                        difpackets.append(_temppacket)
                        # packetsize.append(len(buf))
                        difdictp[_temppacket] = len(buf)
                        src.append(mac_addr(eth.src))
                        dst.append(mac_addr(eth.dst))
                        ipsrc.append(socket.inet_ntoa(ip.src))
                        ipdst.append(socket.inet_ntoa(ip.dst))
                        sport.append(_tempsport)
                        dport.append(_tempdport)
                # tcp connection already created
                # if _temppacket or _temppacket_back is in difdictp add len
                else:
                    _temppacket_back = socket.inet_ntoa(ip.dst) + socket.inet_ntoa(ip.src) + str(_tempdport) + str(
                        _tempsport)
                    if _temppacket in difdictp :
                        difdictp[_temppacket] += len(buf)
                    elif _temppacket_back in difdictp :
                        difdictp[_temppacket_back] += len(buf)
            # no udp
            '''
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data

                _tempsport = udp.sport
                _tempdport = udp.dport

                _temppacket = socket.inet_ntoa(ip.src) + socket.inet_ntoa(ip.dst) + str(_tempsport) + str(_tempdport)
                _temppacket_back = socket.inet_ntoa(ip.dst) + socket.inet_ntoa(ip.src) + str(_tempdport) + str(
                    _tempsport)
                if _temppacket in difdictp:
                    difdictp[_temppacket] += len(buf)
                elif _temppacket_back in difdictp:
                    _temp = 1  # no action
                else:
                    difpackets.append(_temppacket)
                    # packetsize.append(len(buf))
                    difdictp[_temppacket] = len(buf)
                    src.append(mac_addr(eth.src))
                    dst.append(mac_addr(eth.dst))
                    ipsrc.append(socket.inet_ntoa(ip.src))
                    ipdst.append(socket.inet_ntoa(ip.dst))
                    sport.append(_tempsport)
                    dport.append(_tempdport)
            '''

        file.close()

    for i in range(len(difpackets)):
        packetsize.append(difdictp[difpackets[i]])

    ps = pd.Series(packetsize)
    ss = pd.Series(src)
    dd = pd.Series(dst)
    ipss = pd.Series(ipsrc)
    ipdd = pd.Series(ipdst)
    sp = pd.Series(sport)
    dp = pd.Series(dport)
    data = { 'psize': ps, 'src': ss, 'dst': dd, 'ipsrc': ipss, 'ipdst': ipdd, 'sport': sp, 'dport': dp}
    df = pd.DataFrame(data)
    #df.to_csv('/data/ray/pcap/pcap_scpy_005.csv')
    df.to_csv('/data/ray/pcap/pcap_dpkt_multi_dif_004.csv')

if __name__ == '__main__':
    st1 = time.time()
    dpkt_pcap()
    en1 = time.time()
    print(en1 - st1)

