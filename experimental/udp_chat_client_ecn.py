#!/usr/bin/env python
import socket
import sys, select, os
import argparse



# Read a line. Using select for non blocking reading of sys.stdin

def getLine():
	if (sys.platform == 'linux'):
		i,o,e = select.select([sys.stdin],[],[],0.0001)
		for si in i:
			if si == sys.stdin:
				inp = sys.stdin.readline()
				return inp
		return False
	else:
		inp = input(">>")
		return(inp)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Testa suporte ao ECN na camada IP em chat.")
	parser.add_argument("ip_addr", type=str, help="IP destino")
	parser.add_argument("port", type=int, help="Porta destino")
	parser.add_argument("ecn_ip", type=int, help="Valor do ecn a ser usado.")
	args = parser.parse_args()

	host = args.ip_addr
	port = args.port
	ECN = args.ecn_ip

	send_address = (host, port) # Set the address to send to

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_IP)    # Create Datagram Socket (UDP)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Make Socket Reusable
	s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, ECN)
	#s.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 0x03)
	#s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Allow incoming broadcasts
	s.setblocking(False) # Set socket to non-blocking mode
	s.bind(('', port)) #Accept Connections on port
	print("Accepting connections on port", hex(port))
	inp = ""

	while 1:
		try:
			message, address = s.recvfrom(8192) # Buffer size is 8192. Change as needed.
			if message:
				tos_r = s.getsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS)
				print(address, "> ", message)

				print("TOS received: %02X"%tos_r)
				inp = ""
		except:
			pass

		if inp == "":	
			inp = getLine()
			if(inp != False):
				s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, ECN)
				s.sendto(bytes(inp, 'utf-8') , send_address)