# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 25 00:04:23 2017

@author: root
"""

import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import time
import json

start = time.time()
print('start')
print(start)
# data = { 'psize': ps, 'src': ss, 'dst': dd, 'ipsrc': ipss, 'ipdst': ipdd, 'sport': sp, 'dport': dp}
df = pd.read_csv('/data/ray/pcap/pcap_dpkt_multi_dif_003.csv')
ipsrc = df['ipsrc']
ipdst = df['ipdst']
sport = df['sport']
dport = df['dport']
n = len(ipsrc)
print(n)
G = nx.DiGraph()
haship = []  # store diff ipsrc
difdictip = {}  # dict of ip
srcouttimes = []  # connection times [out]
srcoutnumbers = []  # different dst connection numbers [out]
srcintimes = []  # connection times [in]
srcinnumbers = []  # different dst connection numbers [in]
difdictsrcdst = {}
dictsrctimes = {}  # connection times [out]
dictsrcnumbers = {}  # different dst connection numbers [out]
dictdsttimes = {}  # connection times [in]
dictdstnumbers = {}  # different dst connection numbers [in]
dictlinksjson = {}
for i in range(n):
    # diff ipsrc i
    if ipsrc[i] not in difdictip:
        difdictip.setdefault(ipsrc[i], )
        haship.append(ipsrc[i])
    if ipdst[i] not in difdictip:
        difdictip.setdefault(ipdst[i], )
        haship.append(ipdst[i])

    tempipsrcdst = ipsrc[i] + ipdst[i]
    if tempipsrcdst in difdictsrcdst:
        difdictsrcdst[tempipsrcdst] = 1
        G.add_edge(ipsrc[i], ipdst[i], weight=difdictsrcdst[tempipsrcdst])
        dictlinksjson[ipsrc[i] + '-' + ipdst[i]] = difdictsrcdst[tempipsrcdst]
    else:
        difdictsrcdst[tempipsrcdst] = 1
        G.add_edge(ipsrc[i], ipdst[i], weight=1)
        dictlinksjson[ipsrc[i] + '-' + ipdst[i]] = 1

    # ipsrc i in dictsrctimes/dictsrcnumbers, then ipdst was connected to ipsrc
    # calu ipsrc's connections times and numbers
    # in == out ??
    if ipsrc[i] in dictsrctimes:
        dictsrctimes[ipsrc[i]].append(ipdst[i])
        dictsrcnumbers[ipsrc[i]].add(ipdst[i])
    else:
        dictsrctimes.setdefault(ipsrc[i], [])
        dictsrctimes[ipsrc[i]].append(ipdst[i])
        dictsrcnumbers.setdefault(ipsrc[i], set())
        dictsrcnumbers[ipsrc[i]].add(ipdst[i])
    # ipdst
    if ipdst[i] in dictdsttimes:
        dictdsttimes[ipdst[i]].append(ipsrc[i])
        dictdstnumbers[ipdst[i]].add(ipsrc[i])
    else:
        dictdsttimes.setdefault(ipdst[i], [])
        dictdsttimes[ipdst[i]].append(ipsrc[i])
        dictdstnumbers.setdefault(ipdst[i], set())
        dictdstnumbers[ipdst[i]].add(ipsrc[i])

# convert times and numbers to pandas list
for i in range(len(haship)):
    if haship[i] in dictsrctimes:
        srcouttimes.append(len(dictsrctimes[haship[i]]))
        srcoutnumbers.append(len(dictsrcnumbers[haship[i]]))
    else:
        srcouttimes.append(0)
        srcoutnumbers.append(0)
    if haship[i] in dictdsttimes:
        srcintimes.append(len(dictdsttimes[haship[i]]))
        srcinnumbers.append(len(dictdstnumbers[haship[i]]))
    else:
        srcintimes.append(0)
        srcinnumbers.append(0)

#convert dict of links to json
linksjson = []
for i in dictlinksjson:
    item = {}
    mid_index = i.find('-')
    linksrc = i[0:mid_index]
    linkdst = i[mid_index + 1:]
    item["source"] = linksrc
    item["target"] = linkdst
    item["value"] = dictlinksjson[i]
    linksjson.append(item)

layout = nx.random_layout(G)
plt.figure(1)
nx.draw(G, pos=layout, node_color='y')

pr = nx.pagerank(G, alpha=0.85)
print(pr)
nodes = []
pageRankValues = []
for node, pageRankValue in pr.items():
    # print("%s,%.4f" %(node,pageRankValue))
    nodes.append(node)
    pageRankValues.append(pageRankValue)

sortedindex = np.lexsort((nodes, pageRankValues))
#sorted nodes
#npnodes = np.array(nodes)
#sortednodes = npnodes[sortedindex]
#sorted pagerankvalues
#nppageRankValues = np.array(pageRankValues)
#sortedprv = nppageRankValues[sortedindex]
boundaryprv = pageRankValues[sortedindex[int(len(sortedindex) / 10)]]
#convert dict of nodes to json


plt.figure(2)
nx.draw(G, pos=layout, node_size=[2 * x * len(nodes) if x > boundaryprv else 0 for x in pr.values()], node_color=[x * 100 for x in pr.values()], width = 40 / len(nodes), with_labels=False,alpha = 0.8)

finalsrcouttimes = []
finalsrcoutnumbers = []
finalsrcintimes = []
finalsrcinnumbers = []
finalsrcip = []
finalsrcint = []
lengtemp = len(haship)

# necessary ?
for i in range(lengtemp):
    ind = nodes.index(haship[i])
    finalsrcoutnumbers.append(srcoutnumbers[ind])
    finalsrcouttimes.append(srcouttimes[ind])
    finalsrcintimes.append(srcintimes[ind])
    finalsrcinnumbers.append(srcinnumbers[ind])
    # finalsrcint =
    # finalsrcip

outhashsrc = pd.Series(haship)
outnode = pd.Series(nodes)
outpagerankvalue = pd.Series(pageRankValues)
srcouttimes = pd.Series(finalsrcouttimes)
srcoutnumbers = pd.Series(finalsrcoutnumbers)
srcintimes = pd.Series(finalsrcintimes)
srcinnumbers = pd.Series(finalsrcinnumbers)


data = {'outhashsrc': outhashsrc, 'outpagerankvalue': outpagerankvalue, 'srcouttimes': srcouttimes,
        'srcoutnumbers': srcoutnumbers, 'srcintimes': srcintimes, 'srcinnumbers': srcinnumbers}
dff = pd.DataFrame(data)
out = dff.sort_values(by = 'outpagerankvalue', ascending = False)

#convert dict of nodes to json
nodesjson = []
outnodeid = np.array(out['outhashsrc'])
outnodevalue = np.array(out['outpagerankvalue'])
for i in range(outnode.__len__()):
    item = {}
    nodeid = outnodeid[i]
    nodevalue = outnodevalue[i]
    item["id"] = nodeid
    item["group"] = 1
    item["value"] = nodevalue
    nodesjson.append(item)
    print(item)

dictjson = {}
dictjson["nodes"] = nodesjson
dictjson["links"] = linksjson
file_name = 'out_json_005_udp_weight1.json' #通过扩展名指纹文件存储的数据为json格式
with open(file_name,'w') as file_object:
    json.dump(dictjson,file_object)

# dff.to_csv('C:/Users/BladeRay/Desktop/hillstone/pcap_dpkt_test_out_001.csv')
out.to_csv('/data/ray/pcap/pcap_dpkt_multi_out_005_includeudp_weight1.csv')
end = time.time()
print('end')
print(end)
print(end - start)
plt.show()
