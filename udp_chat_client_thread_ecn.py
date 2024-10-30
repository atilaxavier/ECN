#!/usr/bin/env python
import socket
import sys, select, os
import argparse
import threading
import time

class colors:
	'''
	Colors class:reset all colors with colors.reset; two sub classes fg for foreground and bg for background; use as colors.subclass.colorname. i.e. colors.fg.red or colors.bg.greenalso, the generic bold, disable, underline, reverse, strike through, and invisible work with the main class i.e. colors.bold
	'''
	reset = '\033[0m'
	bold = '\033[01m'
	disable = '\033[02m'
	underline = '\033[04m'
	reverse = '\033[07m'
	strikethrough = '\033[09m'
	invisible = '\033[08m'

class fg:
		black = '\033[30m'
		red = '\033[31m'
		green = '\033[32m'
		orange = '\033[33m'
		blue = '\033[34m'
		purple = '\033[35m'
		cyan = '\033[36m'
		lightgrey = '\033[37m'
		darkgrey = '\033[90m'
		lightred = '\033[91m'
		lightgreen = '\033[92m'
		yellow = '\033[93m'
		lightblue = '\033[94m'
		pink = '\033[95m'
		lightcyan = '\033[96m'

class bg:
	black = '\033[40m'
	red = '\033[41m'
	green = '\033[42m'
	orange = '\033[43m'
	blue = '\033[44m'
	purple = '\033[45m'
	cyan = '\033[46m'
	lightgrey = '\033[47m'


def le_entrada_envia_msg(send_address, ECN):
	global my_socket
	global lock_my_socket
	mydata = threading.local()
	mydata.x = "LE_ENTRADA"
	mydata.c = bg.green

	while mydata.x == "LE_ENTRADA":
		try:
			g_entrada = input(mydata.c + "Msg a enviar: ")
			#lock_my_socket.acquire(False)
			my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, ECN.to_bytes(1,'little'))
			n_bytes = my_socket.sendto(bytes(g_entrada, 'utf-8') , send_address)
			#print("Enviou %d bytes"%n_bytes)
			print(colors.reset)
		except (KeyboardInterrupt, EOFError):
			g_entrada = "CTRL-C"
			mydata.x = "FIM"
			print(colors.reset)
			my_socket.shutdown(socket.SHUT_RDWR)
			#my_socket.close()
			#lock_my_socket.release()
			sys.exit(130)
		#if lock_my_socket.locked():
			#lock_my_socket.release()


def le_imprime_rede():
	global my_socket
	global lock_my_socket
	mydata = threading.local()
	mydata.c = bg.red
	mydata.buffsize = 1024
	mydata.buffer = bytearray(b'\0' * mydata.buffsize)
	buff = bytearray(b'*' * mydata.buffsize)

	#print(mydata.c + "Ouvindo socket..." + colors.reset)
	while 1:
		try:
			#lock_my_socket.acquire(False)
			print(mydata.c + "Ouvindo socket..." + colors.reset)
			mydata.message, mydata.address = my_socket.recvfrom(1024) # Buffer size is 8192. Change as needed.
			#(data, ancdata, msg_flags, address) = socket.recvmsg(bufsize[, ancbufsize[, flags]])
			
			#(nbytes, address) = socket.recvfrom_into(buffer[, nbytes[, flags]])
			#nbytes, address = my_socket.recvfrom_into(buff, 1024)
			#print("Recebeu: %d bytes, do endereco: %s, conteudo: %s"%(nbytes, address, str(buff, 'UTF-8')))
			
			#if mydata.message:
			tos_r = my_socket.getsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS)
			print('\n' + mydata.c, mydata.address, "> ", str(mydata.message, 'UTF-8'))
			#print(mydata.c + "TOS received: %s"%tos_r.hex() + colors.reset)
			print(mydata.c + "TOS received: %02X"%tos_r + colors.reset)  #Usar esse se nao tiver o parametro 1 no final do getsockopt
			if lock_my_socket.locked():
				lock_my_socket.release()
		except Exception as e:
			print(e)
			pass
		time.sleep(0.2)


if __name__ == "__main__":
	global my_socket  
	global lock_my_socket
	lock_my_socket = threading.Lock()    

	parser = argparse.ArgumentParser(description="Testa suporte ao ECN na camada IP em chat.")
	parser.add_argument("ip_addr", type=str, help="IP destino")
	parser.add_argument("port", type=int, help="Porta destino")
	parser.add_argument("ecn_ip", type=int, help="Valor do ecn a ser usado.")
	args = parser.parse_args()

	host = args.ip_addr
	port = args.port
	ECN = args.ecn_ip

	send_address = (host, port) # Set the address to send to

	my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_IP)    # Create Datagram Socket (UDP)
	my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Make Socket Reusable
	my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, ECN.to_bytes(1,'little'))
	#s.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 0x03)
	#s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Allow incoming broadcasts
	#my_socket.setblocking(False) # Set socket to non-blocking mode
	my_socket.bind(('', port)) #Accept Connections on port
	print("Accepting connections on port: " + hex(port)+ colors.reset)

	entrada = threading.Thread(target=le_entrada_envia_msg, args=(send_address, ECN, ))
	rede = threading.Thread(target=le_imprime_rede, args=())

	entrada.daemon = False
	rede.daemon = False

	entrada.start() # isso inicia o thread
	rede.start()

	#entrada.join()

	print("Fim do processo principal")
		  
