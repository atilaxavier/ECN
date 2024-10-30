import argparse
from scapy.all import *

def test_ecn_support(target_ip, target_port):
    # Craft SYN packet with ECN flags set
    syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S", options=[(2, b"\x04"), (3, b"\x03")]) # ECN flags set

    # Send SYN packet and wait for response
    response = sr1(syn_packet, timeout=2, verbose=False)
    print("Response: ")
    print(response)

    if response is not None:
        # Check if SYN-ACK packet received and ECN flags are set
        if response.haslayer(TCP) and response[TCP].flags == 0x12:
            tcp_opts = response[TCP].options
            print('TCP_opts: ')
            print(tcp_opts)
            for opt in tcp_opts:
                if isinstance(opt, tuple) and opt[0] == "ECE" and opt[1] == 1:
                    print("ECN support detected on", target_ip, ":", target_port)
                    return True
                else:
                    print("ECN support NOT detected on", target_ip, ":", target_port)
                    return False
        else:
            print("ECN support NOT detected on", target_ip, ":", target_port)
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