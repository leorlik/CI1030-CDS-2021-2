# Leonardo Lima Dionizio
# BCC
# GRR20195124

from scapy.all import *


pcapFile = scapy.utils.PcapReader("trace.pcap")


def getSession(pkt, sDict, typeProto):
  aKey = (pkt['IP'].src, pkt[typeProto].sport, pkt['IP'].dst, pkt[typeProto].dport)
  bKey = (pkt['IP'].dst, pkt[typeProto].dport, pkt['IP'].src, pkt[typeProto].sport)
  if (bKey in sDict):
    aKey = bKey
  if (aKey not in sDict):
    l = []
    l.append(pkt.show(dump=True))
    sDict[aKey] = l
  else:
    sDict[aKey].append(pkt.show(dump=True))

PKG_count = 0
IP_count = 0
TCP_count = 0
UDP_count = 0
ELSE_count = 0
TCP_Dict = {}
UDP_Dict = {}
for pkt in pcapFile:
  PKG_count+=1
  if pkt.proto == 17:
    UDP_count+=1
    IP_count+=1
    getSession(pkt, UDP_Dict, 'UDP')
  elif pkt.proto == 6:
    TCP_count+=1
    IP_count+=1
    getSession(pkt, TCP_Dict, 'TCP')
  else:
    ELSE_count +=1




print("O arquivo \"trace.pcap\" possui:")
print(PKG_count, 'pacotes no total')
print(IP_count, 'pacotes IP')
print(TCP_count, 'pacotes TCP')
print(UDP_count, 'pacotes UDP')
print(len(TCP_Dict), 'sessoes TCP')
print(len(UDP_Dict), 'sessoes UDP')
print(ELSE_count, 'pacotes nao-ip')
