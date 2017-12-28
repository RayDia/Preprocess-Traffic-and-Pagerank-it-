
import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import time
start = time.time()
print('start')
print(start)
#data = { 'psize': ps, 'src': ss, 'dst': dd, 'ipsrc': ipss, 'ipdst': ipdd, 'sport': sp, 'dport': dp}
df = pd.read_csv('/data/ray/pcap/pcap_dpkt_dif_003.csv')
ipsrc = df['ipsrc']
ipdst = df['ipdst']
sport = df['sport']
dport = df['dport']
#n = len(ipsrc)
n = 1000
print(n)
G = nx.DiGraph()
haship = [] #store diff ipsrc
for i in range(n):
    G.add_edge(ipsrc[i], ipdst[i])
layout = nx.kamada_kawai_layout(G)
plt.figure(3)
nx.draw(G, pos=layout, node_color='y', width = 0.1)

plt.show()