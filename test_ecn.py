import platform
import sys
import argparse
from datetime import datetime
from scapy.all import *

def test_ecn_support(target_ip, target_port):
    # Craft SYN packet with ECN flags set
    syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags=0x0c2) # ECN flags set
    #syn_packet = IP(dst=target_ip, tos=0x01) / TCP(dport=target_port, flags=0x0c2) # ECN flags set
    #flags=0x0c2 = (SYN, ECN, CWR)
    #resposta deve ter flags=0x052 = (SYN, ACK, ECN)
    # Send SYN packet and wait for response
    print('Enviando pacote:')
    print(syn_packet, "IP TOS: %s, TCP flags: %s"%(hex(syn_packet[IP].tos), syn_packet[TCP].flags))
    if (sys.platform == 'linux'):
        response = sr1(syn_packet, timeout=5, verbose=False) # so funciona em Linux
    else:
        response = srp1(syn_packet, timeout=5, verbose=False) # em Windows so funciona srp1
    print("Response: ")
    print(response)

    if response is not None:
        # Check if SYN-ACK packet received and ECN flags are set (flags='SAE')
        print("TCP flags:")
        print(response[TCP].flags)
        if response.haslayer(TCP) and response[TCP].flags == 0x052:
            print("TCP ECN support detected on", target_ip, ":", target_port)
            if (response[IP].tos & 0x03):
                print("IP ECN suportado - ECN=%s"%hex(response[IP].tos))
            else:
                print("IP ECN nao detectado - ECN=%s"%(hex(response[IP].tos)))
            return True
        else:
            print("TCP ECN support NOT detected on", target_ip, ":", target_port)
            return False
    else:
        print("No response received from", target_ip, ":", target_port)
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test ECN support on a TCP server.")
    parser.add_argument("target_ip", help="IP address of the target server")
    parser.add_argument("target_port", type=int, help="Port number of the target server")
    args = parser.parse_args()

    print("Testing ECN support on", args.target_ip, ":", args.target_port)
    test_ecn_support(args.target_ip, args.target_port)

    #sudo python3 test_ecn2.py 8.8.8.8 53