'''
Explicit Congestion Notification (ECN) e uma funcionalidade opcional das redes TCP/IP que marca pacotes que passam por partes da rede com congestionamento elevado. O ECN usa os dois bits menos significativos do campo Traffic Class do cabeçalho IPv4 ou IPv6 para codificar quatro pontos de código diferentes: 
00 - Non ECN-Capable Transport, Not-ECT 
01 - ECN Capable Transport(1), ECT(1) 
10 - ECN Capable Transport(0), ECT(0) 
11 - Congestion Experienced, CE 
When both endpoints support ECN they mark their packets with ECT(0) or ECT(1). Routers treat the ECT(0) and ECT(1) codepoints as equivalent
https://www.geeksforgeeks.org/what-is-ecnexplicit-congestion-notification/
ECN Codepoints in IP header:
S. No.	ECT	CE	Codepoint						Sent From	To
1. 		0	0	non-ECT							any 		any
2. 		0	1	ECT(1): ECN Capable Transport	sender 		receiver
3.		1	0	ECT(0): ECN Capable Transport	sender		receiver
4. 		1	1 	CE: Congestion Experienced		router		receiver
[0 0] means non-ECT. That means packet is not ECN supported, So there is no point of marking this packet. If there is congestion then this packet must be dropped instead of marking it.
[0 1] is ECT(0) codepoints means that packet is ECT supported.
[1 0] is ECT(1) codepoint, it also means that packet is ECT enabled. If a packet is ECT(0) or (1) then this packet will not be dropped by the router instead it will be marked.
[1 1] is CE codepoint. When router is congested and packet is ECT enabled then router will mark this packet as CE. Router will flip the 0 bit of ECT codepoint and make it CE. It does not drop the packet, just marks it and transfers to the receiver.

Vamos marcar pacote IP com 01 (ECT(1)) - ECN Capable Transport, nos pacotes enviados no modo sender, e 10 (ECT(0)) - ECN Capable Trasnport, nos pacotes enviados do receiver para o sender.

TCP Flags:
0x0c2 - SYN, ECE, CWR = CES - resposta = EAS = 0x52, significa que TCP suporta ECN
0x0d0 - ACK, ECE, CWR = CEA 
'''
#!/usr/bin/env python

import argparse
from scapy.all import *
'''
packet = IP(dst='201.36.80.57', tos=0x01)/ICMP()

packet = IP(dst='201.36.80.57',tos=0x01, ttl=(1,4))/ICMP()

r = sr(packet)

# OK
packet = IP(dst='201.36.80.57', tos=0x01)/ICMP()
sendp(packet)

packet = IP(dst='201.36.80.57', tos=0x01)/TCP(dport=80, flags=0x0c2)
r = sr1(packet)

# OK
packet = IP(dst='201.36.80.57', tos=0x01)/TCP(dport=80, flags=0x0c2)
r = sendp(packet)

# OK
packet = IP(dst='201.36.80.57', tos=0x01)/TCP(dport=80, flags='CES')
r = sendp(packet)


packet = IP(dst='201.36.80.57', tos=0x01)/TCP(dport=80, flags=0x0c2)
r = sr1(packet)


# TCP ACK ping - deve receber RESET - NOK
packet = IP(dst='201.36.80.57', tos=0x01)/TCP(dport=81, flags='CEA')
r = sendp(packet)

# TCP SIN ping - deve receber ACK (EAS) - OK
packet = IP(dst='201.36.80.57', tos=0x01)/TCP(dport=80, flags='CES')
r = sendp(packet)

import socket
n = socket.gethostname()
my_ip = socket.gethostbyname(n)
#'100.84.58.105'

conf.iface  - para informar interface padrão
NetworkInterface_Win - Intel 5G Solution 5000
'''
#packet = IP(src='100.84.58.105', dst='201.36.80.57', tos=0x01)/TCP(dport=80, flags='CES') #servidor lab
packet = IP(src='100.84.58.105', dst='142.250.79.46', tos=0x01)/TCP(dport=443, flags='CES') # YouTube


r = sr1(packet, timeout=5, iface='Intel 5G Solution 5000')
print(r[TCP].flags)
print(r[IP].tos)


# Teste Google
packet = IP(src=my_ip, dst='142.250.79.46', tos=0x01)/TCP(dport=443, flags='CES')
r = srp(packet, timeout=5)
(<Results: TCP:1 UDP:0 ICMP:0 Other:0>, <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>)
>>> r[0].summary()
IP / TCP 100.82.160.53:ftp_data > 142.250.79.46:https SEC ==> IP / TCP 142.250.79.46:https > 100.82.160.53:ftp_data SA


# Para ouvir
a = sniff(filter="icmp and host 66.35.250.151", count=2)
a = sniff(iface="wifi0", prn=lambda x: x.summary())
sniff(iface = 'Intel 5G Solution 5000', prn=lambda x:x.summary())

sniff(iface = 'Intel 5G Solution 5000', prn=lambda x:x.show())

p = sniff(iface = 'Intel 5G Solution 5000', prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{IP:%IP.tos%\n}{Raw:%Raw.load%\n}"), count=1)

p = sniff(iface = 'Intel 5G Solution 5000', filter='srp[0]c 104.208.16.92', prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{IP:%IP.tos%\n}{Raw:%Raw.load%\n}"), count=2)

>>> p[0][IP]
<IP  version=4 ihl=5 tos=0x20 len=52 id=20574 flags=DF frag=0 ttl=105 proto=tcp chksum=0x4392 src=104.208.16.92 dst=100.82.160.53 |<TCP  sport=https dport=62251 seq=2650014861 ack=3831556759 dataofs=8 reserved=0 flags=A window=16388 chksum=0xb7b3 urgptr=0 options=[('NOP', None), ('NOP', None), ('SAck', (3831556758, 3831556759))] |>>
>>> p[0][TCP]
<TCP  sport=https dport=62251 seq=2650014861 ack=3831556759 dataofs=8 reserved=0 flags=A window=16388 chksum=0xb7b3 urgptr=0 options=[('NOP', None), ('NOP', None), ('SAck', (3831556758, 3831556759))] |>
>>> p[0][IP].tos
32


a=sniff(filter="tcp and ( port 25 or port 110 )", prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s, TCP.flags% : %TCP.payload%"))

# 142.251.135.110 - youtube
a=sniff(filter="host 142.251.135.110", prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% : %TCP.payload%, IP.TOS: %IP.tos%"))

a=sniff(filter="host youtube.com and (udp or tcp)", count=50, prn=lambda x: x.sprintf("IP.proto: %s,IP.proto%, %IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% : %TCP.payload%, IP.TOS: %s,IP.tos%"))

'''
IP.proto: tcp, 100.82.160.53:60131 -> 163.116.228.35:https  PA : Raw, IP.TOS: 0x2
IP.proto: tcp, 163.116.228.35:https -> 100.82.160.53:60131   A : , IP.TOS: 0x20
IP.proto: tcp, 52.104.85.39:https -> 100.82.160.53:51022   A : , IP.TOS: 0x20
IP.proto: tcp, 163.116.228.35:https -> 100.82.160.53:60131   A : , IP.TOS: 0x20
IP.proto: tcp, 104.208.16.88:https -> 100.82.160.53:51018   A : , IP.TOS: 0x20
IP.proto: tcp, 52.104.85.39:https -> 100.82.160.53:51022   A : Raw, IP.TOS: 0x22
IP.proto: tcp, 52.104.85.39:https -> 100.82.160.53:51022   A : Raw, IP.TOS: 0x22
IP.proto: tcp, 52.104.85.39:https -> 100.82.160.53:51022   A : Raw, IP.TOS: 0x22
IP.proto: tcp, 52.104.85.39:https -> 100.82.160.53:51022  PA : Raw, IP.TOS: 0x22
'''


# Async sniffer
t = AsyncSniffer()
t.start()
print("hey")
hey
[...]
results = t.stop()

t = AsyncSniffer(filter="host youtube.com and (icmp or udp or tcp or other)", prn=lambda x: x.sprintf("IP.proto: %s,IP.proto%, %IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% : %TCP.payload%, IP.TOS: %s,IP.tos%"))
t.start()
print("hey")
hey
[...]
r = t.stop()
'''
IP.proto: tcp, 163.116.228.35:https -> 100.82.160.53:60131  PA : Raw, IP.TOS: 0x22
IP.proto: tcp, 163.116.228.35:https -> 100.82.160.53:60131  PA : Raw, IP.TOS: 0x22
IP.proto: tcp, 163.116.228.35:https -> 100.82.160.53:60131  PA : Raw, IP.TOS: 0x22
IP.proto: tcp, 100.82.160.53:60131 -> 163.116.228.35:https   A : , IP.TOS: 0x0
IP.proto: tcp, 100.82.160.53:60131 -> 163.116.228.35:https  PA : Raw, IP.TOS: 0x2
IP.proto: tcp, 100.82.160.53:60131 -> 163.116.228.35:https  PA : Raw, IP.TOS: 0x2
IP.proto: tcp, 100.82.160.53:60131 -> 163.116.228.35:https  PA : Raw, IP.TOS: 0x2
IP.proto: tcp, 100.82.160.53:60131 -> 163.116.228.35:https  PA : Raw, IP.TOS: 0x2
...
IP.proto: tcp, 163.116.228.35:https -> 100.82.160.53:60131  PA : Raw, IP.TOS: 0x22
IP.proto: tcp, 100.82.160.53:60131 -> 163.116.228.35:https   A : , IP.TOS: 0x0
IP.proto: tcp, 100.82.160.53:60131 -> 163.116.228.35:https  PA : Raw, IP.TOS: 0x2
IP.proto: tcp, 163.116.228.35:https -> 100.82.160.53:60131   A : , IP.TOS: 0x20
IP.proto: tcp, 100.82.160.53:52167 -> 20.143.38.2:https  FA : , IP.TOS: 0x0
>>> r
<Sniffed: TCP:2421 UDP:21 ICMP:0 Other:3>

>>> r[0]
<IP  version=4 ihl=5 tos=0x22 len=344 id=12916 flags=DF frag=0 ttl=53 proto=tcp chksum=0x85ea src=163.116.228.35 dst=100.82.160.53 |<TCP  sport=https dport=60131 seq=1643258959 ack=2782644112 dataofs=5 reserved=0 flags=PA window=32700 chksum=0x9002 urgptr=0 |<Raw  load='\x17\x03\x03\x01+\x1cTXC\\xfdo\\x81\x00v5\x19\\x8e\\x9f\\xa39\\xa7\\xf3\\xe0\\xef\\xecv\\xe2\x13P]&"\\xed\\xd1\x0c)\\xe2\\xad\\xcaK\x19\\xb7\\xa8sD\\xaclf\\xf2\x12\\xa4\\x95\\x91\\xdd\\xc9"\\xa2\\x9c\\x98\\xd8]\x10\x0c\\xe1\x12\\xa7A\\xcd.\\xb4ف\\xec\\xa6.e\\xa0h\\xab\\x87\\xfd\\x9c\x0fX?t\\xb8\\x90h\\xb9xp@\\xb2<\\xea\\x95Ꮚ\x0c\\xbb\\xa3\\xc1\\x85]\x06ll1\x02\x01\\xf6/\\xbf{\x02JRV\\xe0Q\rz=\\xd7\\xfeU\\xb8:\\x96\\x9f\\xc4a\\x90\x074hN\x18\\x85~\\xa9\\xffE,}\\x9b\\x8f\\xdaJ\\xd6\\xe17\\xc2\x04\\x8d\\xc5\x13\\xfb\\xba\\xf8\\x83\\xe5\\xb6\\xce1k]\\xb6b1\\xd8|\\x96\\xf0*\rCى\\xceZR\x132\x15\\x92\\xd1uI\\xe8.\\xfa:\\x89\x07\\xdb\\xd1\\xf4\x1a\x15r\nƮ!\\xb74\\xc4u\x15\\xae\x1cg\x03\\xf4d\\x87\\xcf\\xe2rJ\x04Xk\\xb9O+\\x92N\\xba\\xe9\x05\\x96\t\\x9f\\xd9ǔ\\xa6\\xa2\\xd3\\xe0!\x0f\\x90\\xfbX\\x9d\\xa1\\xb48\x1bf$d\\x84\\xbd\\xb3\\xf8C\x04\\xea\\x89bԙj\\xa8\\x9c0[\\xc9bH,[Q8\\xbc\\xab\\xde\x1f\t\\xdb\\xfbs&Z\\xb8+-G\\xa0\\xbf\x08=\x16\\xe2\\xf0\'<\x0f' |>>>

r[0][IP].tos
34
>>> hex(r[0][IP].tos)
'0x22'
DSCP = 000010 - CS6 - Internetwork Control
ECN = 10

IP protocol numbers:
ICMP: 1
TCP: 6
UDP: 17

l = len(r)
for i in range(l):
    if(r[i].version==4):
        if(r[i][IP].proto not in [1, 6]):
            print("Proto: %d, TOS: %s"%(r[i][IP].proto, hex(r[i][IP].tos)))
    else:
        print("Protocol version %d, packet %d"%(r[i].version, i))
Protocol version 6, packet 16
Protocol version 6, packet 18
Protocol version 6, packet 66
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x20
Proto: 17, TOS: 0x0
Protocol version 6, packet 1402
Proto: 17, TOS: 0x0
Proto: 17, TOS: 0x0

l = len(r)
for i in range(l):
    if(r[i].version==4):
        if( r[i][IP].tos & 0x03 ):
            print("src:port - %s:%d; dst:port %s:%d- ; Proto: %d, TOS: %s"%(r[i][IP].src, r[i][TCP].sport, r[i][IP].dst, r[i][TCP].dport, r[i][IP].proto, hex(r[i][IP].tos)))
    else:
        print("Protocol version %d, packet %d"%(r[i].version, i))


'''

# OU
t = AsyncSniffer(iface="enp0s3", count=200)
t.start()
t.join()  # this will hold until 200 packets are collected
results = t.results
print(len(results))
200




'''
sniff() uses Berkeley Packet Filter (BPF) syntax (the same one as tcpdump), here are some examples:
https://biot.com/capstats/bpf.html
Packets from or to host:

host x.x.x.x
Only TCP SYN segments:

tcp[tcpflags] & tcp-syn != 0
Everything ICMP but echo requests/replies:

icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply

'''
t = AsyncSniffer(filter="ip[tos] & 3 != 0", prn=lambda x: x.sprintf("IP.proto: %s,IP.proto%, %IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% : %TCP.payload%, IP.TOS: %s,IP.tos%"))
t.start()
print("hey")
hey
[...]
r = t.stop()