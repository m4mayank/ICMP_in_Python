#!/usr/bin/python3

import ping

from argparse import ArgumentParser

def create_parser():
    parser = ArgumentParser(description="Ping")
    parser.add_argument("Destination",help="The destination IP address to ping. Example : 192.168.10.1 or www.google.com")
    parser.add_argument("--count", type=int, help="Number of ping packets to send", default=5)
    parser.add_argument("--version","-v",action="version",version='Ping 1.0')
    return parser


if __name__ == "__main__":
    try:
        args=create_parser().parse_args()
    except:
        print("Please provide the destination address to ping")
    ping.ping_loop(args.Destination, count=args.count)
