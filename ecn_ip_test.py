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

import platform
import sys
import argparse
import time
from datetime import datetime
from scapy.all import *
from colorama import Fore, Back, Style
import socket


def test_ecn_ip_support(target_ip, target_port, ecn_ip):
	# Craft SYN packet with ECN flags set
	source_port = 62321
	tout = 5
	pIP = IP(dst=target_ip, tos=ecn_ip) # ECN flags set
	pUDP = UDP(dport=target_port)
	pDATA = "Testando ECN IP"
	packet = pIP / pUDP / pDATA
	#packet = IP(dst=target_ip, tos=ecn_ip) / UDP(dport=target_port) / "Testando ECN IP" # ECN flags set
	print('Enviando pacote:')
	print(packet, "Conteudo: %s, IP TOS: %s"%(packet[UDP].load, hex(packet[IP].tos)))

	flt = "src %s"%(target_ip)
	#flt = "src port %d"%(target_port)
	#("ip proto ICMP")
	#flt = "udp src port %d"%(target_port)
	#flt = ("udp dst port %d"%(source_port))
	#flt = "udp"
	print(flt)

	if (sys.platform == 'linux'):
		response = send(packet, return_packets=True) 
	else:
		response = sendp(packet, return_packets=True) # precisa ser sendp  em windows
	print(response)
	#t = AsyncSniffer(filter=flt, count=1)
	#t.start()
	print("Pacote enviado. Aguardando resposta...")
	print("--------------------------------------")
	meu_pacote = False
	while not meu_pacote:
		r = sniff(filter=flt, count=2, timeout=tout)

		#t.join(timeout=5)  # this will hold until count packets are collected
		#r = t.results
		print(r)

		#if r is not None:
		if len(r) > 0:
			for i in range(len(r)):
				if "ICMP" in r[i]:
					print("ICMP de %s"%r[i][IP].src)
					r[i].show2()
				else:
					if "TCP" in r[i]:
						print("TCP de %s"%r[i][IP].src)
					else:
						if "UDP" in r[i]:
							print("Resposta recebida de: %s:%d na porta: %d, conteudo: %s, com TOS IP: %s"%(r[i][IP].src, r[i][UDP].sport, r[i][UDP].dport, r[i][UDP].load, hex(r[i][IP].tos)))
							if(r[i][IP].tos & 0x03):
								print(Fore.GREEN + "ECN IP suportado entrada. TOS: %s"%hex(r[i][IP].tos) + Style.RESET_ALL)
							else:
								print(Fore.RED + "ECN IP NAO suportado entrada. TOS: %s"%hex(r[i][IP].tos) + Style.RESET_ALL)
							meu_pacote = True
						else:
							print("Other")
							r[i].show2
		else:
			print("Nao recebeu resposta em %d segundos"%tout)
			break

def srv_test_ecn_ip_support(target_port, ecn_ip):
	#Estabelecendo socket para receber pacotes UDP
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	hostname = socket.gethostname()
	IPAddr = socket.gethostbyname(hostname)
	print('Fazendo socket bind para IP: %s, porta: %d'%(IPAddr, target_port))
	sock.bind((IPAddr,target_port))
	sock.setblocking(0)

	#flt = ("udp dst port %d)"%(target_port))
	
	flt = ("dst port %d"%(target_port))
	data = ''
	addr = ''
	try:
		while True:
			try:
				data, addr = sock.recvfrom(1024)
			except socket.error:
				pass
			else:
				print("Recebeu no socket %s de %s"%(data, addr))
			t = AsyncSniffer(filter=flt, count=1)
			t.start()
			t.join()  # this will hold until count packets are collected
			print("Dia e hora: %s"%(datetime.now()))
			r = t.results
			print(r)
			if("ICMP" in r[-1]):
				print("ICMP")
				r[-1].show2()
			else: 
				if("TCP" in r[-1]):
					print("TCP de %s"%r[-1][IP].src)
					#r[-1].show2()
				else:
					if ("UDP" in r[-1]):
						print("teste recebido de: %s:%d na porta: %d, conteudo: %s, com TOS IP: %s"%(r[-1][IP].src, r[-1][UDP].sport, r[-1][UDP].dport, r[-1][UDP].load, hex(r[-1][IP].tos)))
						if r[-1][IP].tos & 0x03:
							print(Fore.GREEN + "ECN IP suportado entrada. TOS: %s"%hex(r[-1][IP].tos) + Style.RESET_ALL)
						else:
							print(Fore.RED + "ECN IP NAO suportado entrada. TOS: %s"%hex(r[-1][IP].tos) + Style.RESET_ALL)
						packet = IP(dst=r[-1][IP].src, tos=ecn_ip) / UDP(sport = r[-1][UDP].dport, dport=r[-1][UDP].sport) / "Resposta a teste ECN IP" # ECN flags set
						time.sleep(1)
						print('Respondendo com:')
						print(packet, "Conteudo: %s, IP TOS: %s"%(packet[UDP].load, hex(packet[IP].tos)))
						if sys.platform == 'linux':
							rp = send(packet, return_packets=True, count=3)
						else:
							rp = sendp(packet, return_packets=True)
						print(rp)
			print("Dia e hora: %s"%(datetime.now()))
			print("---------------")
			#t.stop()
	except KeyboardInterrupt:
			print("Interrompido pelo usuario")
			pass


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Testa suporte ao ECN na camada IP. Usa pacotes UDP e pode atuar como servidor ou cliente. No modo servidor tecle s para sair.")
	parser.add_argument("srv_cli", help="Act as server or client.")
	parser.add_argument("ip_addr", help="IP address of the target server or originating client")
	parser.add_argument("port", type=int, help="Port number of the target server")
	parser.add_argument("ecn_ip", type=int, help="Valor do ecn a ser usado.")
	args = parser.parse_args()

	if(args.srv_cli=='cli'):
		print("Testando suporte ECN IP em: ", args.ip_addr, ":", args.port, " ECN: ", hex(args.ecn_ip))
		test_ecn_ip_support(args.ip_addr, args.port, args.ecn_ip)
	else:  
		print("Escutando pacotes UDP na porta %d"%args.port)
		srv_test_ecn_ip_support(args.port, args.ecn_ip)
