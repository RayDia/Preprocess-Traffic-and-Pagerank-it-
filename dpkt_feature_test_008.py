#this version is remove duplicate packets
import pandas as pd
import numpy as np
import dpkt
import datetime
import socket
import time

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
#ip2int = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def dpkt_pcap():
    dir(dpkt)
    f = open('/data/ray/pcap/localhost-170918-00001852.pcap', 'rb')
    #f = open('/data/ray/pcap/example_network_traffic.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)

    # num = 0
    for ts, buf in pcap:
        # num += 1


        # print(num)
        #print(str(datetime.datetime.utcfromtimestamp(ts)))

        eth = dpkt.ethernet.Ethernet(buf)
        #print('eth')
        #print(eth)
        #print(eth.__hdr__)
        #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        #src.append(mac_addr(eth.src))
        #dst.append(mac_addr(eth.dst))
        ip = eth.data
        #print('ip')
        #print(ip)
        #print(socket.inet_ntoa(ip.src))
        #print(socket.inet_ntoa(ip.dst))
        try:
            socket.inet_ntoa(ip.src)
            socket.inet_ntoa(ip.dst)
        except:
            continue
        tempsport = ''
        tempdport = ''
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            # print('tcp')
            # print(tcp)

            #print('sport')
            #print(tcp.sport)
            #print('dport')
            #print(tcp.dport)
            tempsport = tcp.sport
            tempdport = tcp.dport
            #sport.append(tcp.sport)
            #dport.append(tcp.dport)
            '''
            print('http.uri')
            http_ = tcp.data
            print('http')
            print(http_)
            print(http_.title)
            '''
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            # print('udp')
            # print(udp)

            # print('sport')
            #print(udp.sport)
            # print('dport' )
            #print(udp.dport)
            tempsport = udp.sport
            tempdport = udp.dport
            #sport.append(udp.sport)
            #dport.append(udp.dport)
            '''
            print('http.uri')  
            http_ = udp.data
            print('http')
            print(http_)
            print(http_.title)
            '''
        _temppacket = socket.inet_ntoa(ip.src) + socket.inet_ntoa(ip.dst) + str(tempsport) + str(tempdport)
        _temppacket_back = socket.inet_ntoa(ip.dst) + socket.inet_ntoa(ip.src) + str(tempdport) + str(tempsport)
        if _temppacket in difdictp:
            difdictp[_temppacket] += len(buf)
        elif _temppacket_back in difdictp:
            _temp = 1 # no action
        else:
            difpackets.append(_temppacket)
            #packetsize.append(len(buf))
            difdictp[_temppacket] = len(buf)
            src.append(mac_addr(eth.src))
            dst.append(mac_addr(eth.dst))
            ipsrc.append(socket.inet_ntoa(ip.src))
            ipdst.append(socket.inet_ntoa(ip.dst))
            sport.append(tempsport)
            dport.append(tempdport)


        '''
        if temppacket not in difpackets:
            difpackets.append(temppacket)
            packetsize.append(len(buf))
            src.append(mac_addr(eth.src))
            dst.append(mac_addr(eth.dst))
            ipsrc.append(socket.inet_ntoa(ip.src))
            ipdst.append(socket.inet_ntoa(ip.dst))
            sport.append(tempsport)
            dport.append(tempdport)
        else:
            packetsize[difpackets.index(temppacket)] += len(buf)
        '''
    f.close()

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
    df.to_csv('/data/ray/pcap/pcap_dpkt_dif_008.csv')

if __name__ == '__main__':
    st1 = time.time()
    dpkt_pcap()
    en1 = time.time()
    print(en1 - st1)

