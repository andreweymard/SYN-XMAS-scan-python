#!/usr/bin/python3

import time
import logging
from scapy.all import *
import argparse

parser = argparse.ArgumentParser(description='IMPORTANT: RUN AS SUDO. Supports SYN or XMAS scan with IPv4 address')     #Library argparse is used to pass
parser.add_argument("type", help="Use either syn or xmas to your preference")                                           #arguments through the teminal.
parser.add_argument("ip", help="Provide IPv4 address to scan here")
args = parser.parse_args()

closed_ports = 0
open_ports = []

def is_up(ip):      #Checks if host is up using ICMP before scanning ports
    icmp_resp = sr1(IP(dst=ip)/ICMP(), verbose=0, timeout=1)
    if icmp_resp == None:
        return False
    else:
        print("Host is up. Continuing...")
        return True

if __name__ == '__main__':
    start_time = time.time_ns()
    ports = range(1, 1024)

    print("Checking if Host is up...")

    if is_up(args.ip):
        if args.type == "syn":      #SYN scan starts here
            for port in ports:
                syn_resp = sr1(IP(dst=args.ip)/TCP(dport=port, flags="S"), verbose=0, timeout=1)
                if syn_resp == None:
                    closed_ports += 1
                elif syn_resp.getlayer(TCP).flags=="SA":
                    open_ports.append(port)
                else:
                    closed_ports += 1
            print("\nSYN scan results for IP", args.ip)
            if len(open_ports) != 0:
                print("Port(s)", end=" ")
                for i in open_ports:
                    print(i, end=" ")
                print("are open.")
            else:
                print("No open ports found.")
            print(closed_ports, "closed ports were scanned.")

        elif args.type == "xmas":   #XMAS scan starts here
            for port in ports:
                xmas_resp = sr1(IP(dst=args.ip)/TCP(dport=port, flags="UPF"), verbose=0, timeout=1)
                if xmas_resp == None:
                    open_ports.append(port)
                elif (xmas_resp.getlayer(TCP).flags == "R" or "RA"):
                    closed_ports += 1
                else:
                    open_ports.append(port)
            print("\nXMAS scan results for IP", args.ip)
            if len(open_ports) != 0:
                print("Port(s)", end=" ")
                for i in open_ports:
                    print(i, end=" ")
                print("are open.")
            else:
                print("No open ports found")
            print(closed_ports, "closed ports were scanned.")

        else:
            logging.error(" Please set scan type as either \"syn\" or \"xmas\".")
            exit()

    else:
        print("Host is down. Exiting...")
        exit()

    print("\nScan completed on ", time.ctime(), " in " , (time.time_ns()-start_time)/1000000000 , " seconds")
