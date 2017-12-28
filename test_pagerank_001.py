#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 12 14:31:08 2017

@author: root
"""
import matplotlib.pyplot as plt
import networkx as nx

G = nx.DiGraph()
G.add_edge(4, 0, weight = 1)
G.add_edge(2, 0, weight = 1)
G.add_edge(2, 4, weight = 1)
G.add_edge(4, 2, weight = 1)
G.add_edge(5, 4, weight = 1)
G.add_edge(1, 4, weight = 1)
G.add_edge(1, 5, weight = 1)
G.add_edge(3, 5, weight = 1)

G.add_edge(3, 1, weight = 3)
layout = nx.spring_layout(G)
plt.figure(1)
nx.draw(G, pos=layout, node_color='y')

pr=nx.pagerank(G,alpha=0.85)
print(pr)
for node, pageRankValue in pr.items():
    print("%d,%.4f" %(node,pageRankValue))

plt.figure(2)
nx.draw(G, pos=layout, node_size=[x * 6000 for x in pr.values()],node_color='#99CC99',with_labels=True, font_color = '#990033', edge_color = '#666666')
plt.show()

'''
4,0.2832
0,0.2595
2,0.1821
5,0.1254
1,0.0880
3,0.0618


4,0.2818
0,0.2585
2,0.1814
5,0.1201
1,0.0965
3,0.0616

4,0.2812
0,0.2580
2,0.1810
5,0.1175
1,0.1008
3,0.0615
'''