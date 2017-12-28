#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Oct 23 10:43:34 2017

@author: root
"""
import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import time

#lc=pd.DataFrame(pd.read_csv('LoanStats3a.csv',header=1))
df = pd.read_csv('/data/ray/pcap/pcap_dpkt_test_out_009.csv')
haship = df['outhashsrc']
pagerankvalues = df['outpagerankvalue']
finalsrcouttimes = df['srcouttimes']
finalsrcoutnumbers = df['srcoutnumbers']
finalsrcintimes = df['srcintimes']
finalsrcinnumbers = df['srcinnumbers']

outhaship = pd.Series(haship)
outpagerankvalues = pd.Series(pagerankvalues)
srcouttimes = pd.Series(finalsrcouttimes)
srcoutnumbers = pd.Series(finalsrcoutnumbers)
srcintimes = pd.Series(finalsrcintimes)
srcinnumbers = pd.Series(finalsrcinnumbers)

data = {'outhashsrc': outhaship, 'outpagerankvalues': outpagerankvalues, 'srcouttimes': srcouttimes,
        'srcoutnumbers': srcoutnumbers, 'srcintimes': srcintimes, 'srcinnumbers': srcinnumbers}
dff = pd.DataFrame(data)
out = dff.sort_values(by = 'outpagerankvalues', ascending = False)

#dff.to_csv('C:/Users/BladeRay/Desktop/hillstone/pcap_dpkt_test_out_001.csv')
out.to_csv('/data/ray/pcap/pcap_dpkt_test_sortedout_009.csv')