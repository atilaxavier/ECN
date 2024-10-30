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
000. .... .... = Reserved (not set)
...0 .... .... = Accurate ECN (not set)
.... 1... .... = Congestion Window Reduction (set)
.... .1.. .... = ECN-Echo (set)
.... ..0. .... = Urgent (not set)
.... ...0 .... = Acknowledgment (not set)
.... .... 0... = Push (not set)
.... .... .0.. = Reset (not set)
.... .... ..1. = SYN (set)
.... .... ...0 = FIN (no set)

0x0c2 - SYN, ECE, CWR = CES (SEC) - resposta = EAS (SAE) = 0x052, significa que TCP suporta ECN
0x0d0 - ACK, ECE, CWR = CEA 
'''
#!/usr/bin/env python

import platform
import sys
import argparse
import time
from datetime import datetime
from scapy.all import *


def test_ecn_tcp_ip_support(target_ip, target_port, ecn_ip):
	# Craft SYN packet with ECN flags set
	tout = 5
	packet = IP(dst=target_ip, tos=ecn_ip) / TCP(dport=target_port, flags=0x0c2) # ECN flags set TCP e IP
	print('Enviando pacote:')
	print(packet, "IP TOS: %s, TCP flags: %s"%(hex(packet[IP].tos), packet[TCP].flags))
	'''
	response = srp1(packet, timeout=5, verbose=False)

	print("Response: ")
	print(response)

	if response is not None:
		# Check if TCP packet received and IP ECN flags are set 
		print("ECN field:")
		print(hex(response[IP].tos))
		if response.haslayer(IP) and response[IP].tos > 0x00:
			print("ECN IP support detected on", target_ip, ":", target_port)
			return True
		else:
			print("ECN IP support NOT detected on", target_ip, ":", target_port)
			return False
	else:
		print("No response received from", target_ip, ":", target_port)
		return False
	'''
	flt = "tcp src port %d"%(target_port)
	

	print(flt)
	if sys.platform == 'linux':
		response = sendp(packet, return_packets=True)
	else:
		response = sendp(packet, return_packets=True) # precisa ser sendp  em windows
	print(response)
	#t = AsyncSniffer(filter=flt, count=1)
	#t.start()
	print("Pacote enviado. Aguardando resposta...")
	r = sniff(filter=flt, count=1, timeout=tout)
	
	#t.join(timeout=5)  # this will hold until count packets are collected
	#r = t.results
	print(r)
	#if r is not None:
	if len(r) > 0:
		print("Resposta recebida de: %s:%d na porta: %d, com TOS IP: %s e flags TCP: %s"%(r[-1][IP].src, r[-1][TCP].sport, r[-1][TCP].dport, hex(r[-1][IP].tos), r[-1][TCP].flags))
		if(r[-1][IP].tos & 0x03):
			print("ECN IP suportado")
		else:
			print("ECN IP NAO suportado")
		if(r[-1][TCP].flags == 0x052):
			print("ECN TCP suportado")
		else:
			print("ECN TCP NAO suportado")
	else:
		print("Nao recebeu resposta em %d segundos"%tout)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Testa suporte ao ECN na camada IP. Usa pacotes TCP e pode atuar como servidor ou cliente. No modo servidor tecle s para sair.")
	parser.add_argument("srv_cli", help="Act as server or client.")
	parser.add_argument("ip_addr", help="IP address of the target server or originating client")
	parser.add_argument("port", type=int, help="Port number of the target server")
	parser.add_argument("ecn_ip", type=int, help="Valor do ecn a ser usado.")
	args = parser.parse_args()

	if(args.srv_cli=='cli'):
		print("Testando suporte ECN TCP e IP em: ", args.ip_addr, ":", args.port, " ECN: ", hex(args.ecn_ip))
		test_ecn_tcp_ip_support(args.ip_addr, args.port, args.ecn_ip)
	else:  
		print("Escutando pacotes TCP na porta %d"%args.port)
		flt = ("tcp dst port %d"%(args.port))

		try:
			while True:
				t = AsyncSniffer(filter=flt, count=1)
				t.start()
				t.join()  # this will hold until count packets are collected
				print("Dia e hora: %s"%(datetime.now()))
				r = t.results
				print(r)
				print("teste recebido de: %s:%d na porta: %d, com TOS IP: %s e TCP flags: %s"%(r[-1][IP].src, r[-1][TCP].sport, r[-1][TCP].dport, hex(r[-1][IP].tos), r[-1][TCP].flags))
				packet = IP(dst=r[-1][IP].src, tos=args.ecn_ip) / TCP(sport = r[-1][TCP].dport, dport=r[-1][TCP].sport, flags=0x052) # ECN flags set
				time.sleep(1)
				print('Respondendo com:')
				print(packet, "IP TOS: %s, TCP flags: %s"%(hex(packet[IP].tos), packet[TCP].flags))
				if sys.platform == 'linux':
					rp = sendp(packet, return_packets=True)
				else:
					rp = sendp(packet, return_packets=True)
				print(rp)
				print("Dia e hora: %s"%(datetime.now()))
				#t.stop()
		except KeyboardInterrupt:
				print("Interrompido pelo usuario")
				pass
