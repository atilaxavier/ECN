'''
IP addresses tested so far:
apple.com - 17.178.96.59, 17.172.224.47, 17.142.160.59 - Doesn't support ECN
google.com - - Doesn't support ECN
facebook.com - 185.60.216.35 - Doesn't support ECN
nsnam.org - 143.215.76.161 - Doesn't support ECN
thoth.cs.usr.edu - 169.235.30.15
youtube.com - 172.217.16.110
ethz.ch - 129.132.128.139
'''

from scapy.all import *

sport = random.randint(1024,65535)

# SYN
ip=IP(src='172.31.36.11',dst='10.221.232.218')
#SYN=TCP(sport=sport,dport=443,flags='SEC',seq=1000) #set the SYN, CWR and ECE flags on
SYN=TCP(sport=sport,dport=80,flags=0x0c2,seq=1000) #set the SYN, CWR and ECE flags on

SYN.sprintf('%TCP.flags%')
SYNACK=sr(ip/SYN, iface = 'enp0s31f6')[0]

# If the ECE bit is turned on along with the SYN ACK, then the website supports ECN.
# Vai mostrar SAE nos flags
print(SYNACK.summary())
print(SYNACK[0])
