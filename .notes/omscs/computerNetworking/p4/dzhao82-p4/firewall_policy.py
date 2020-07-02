#!/usr/bin/python CS 6250 Summer 2020 - Project 4 - SDN Firewall build
# atlas-v13

from pyretic.lib.corelib import * 
from pyretic.lib.std import * 
from pyretic.lib.query import packets 
from pyretic.core import packet

def make_firewall_policy(config):
    rules = []

    for entry in config:
        print("ENTRY: ", entry)
        # [{
        #     'macaddr_dst': '-', 
        #     'protocol': 'T', 
        #     'rulenum': '1', 
        #     'port_src': '-', 
        #     'ipproto': '-', 
        #     'ipaddr_dst': '-', 
        #     'macaddr_src': '-', 
        #     'port_dst': '1080', 
        #     'ipaddr_src': '-'
        # }]
        # rule = match(dstport=1080, ethtype=packet.IPV4, protocol=packet.TCP_PROTO)
        rule = match(ethtype=packet.IPV4)
        if entry['macaddr_src']=='-' and entry['macaddr_dst']=='-' and entry['ipaddr_src']=='-' and entry['ipaddr_dst']=='-' and entry['port_src']=='-' and entry['port_dst']=='-' and entry['protocol']=='-':
            rule = match()
        if entry['macaddr_src'] != '-':
            rule = rule & match(srcmac=EthAddr(entry['macaddr_src']))
        if entry['macaddr_dst'] != '-':
            rule = rule & match(dstmac=EthAddr(entry['macaddr_dst']))
        if entry['ipaddr_src'] != '-':
            rule = rule & match(srcip=IPAddr(entry['ipaddr_src']))
        if entry['ipaddr_dst'] != '-':
            rule = rule & match(dstip=IPAddr(entry['ipaddr_dst']))
        if entry['port_src'] != '-':
            rule = rule & match(srcport=int(entry['port_src']))
        if entry['port_dst'] != '-':
            rule = rule & match(dstport=int(entry['port_dst']))
        if entry['protocol'] != '-':
            if entry['protocol'] == 'T':
                rule = rule & match(protocol=6)
            elif entry['protocol'] == 'U':
                rule = rule & match(protocol=17)
            elif entry['protocol'] == 'I':
                rule = rule & match(protocol=1)
            elif entry['protocol'] == 'B':
                rule = rule & (match(protocol=6) | match(protocol=17))
            elif entry['protocol'] == 'O':
                rule = rule & match(protocol=int(entry['ipproto']))

        rules.append(rule) 
        pass

    allowed = ~(union(rules))

    return allowed
