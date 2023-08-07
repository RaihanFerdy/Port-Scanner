import socket, threading, os
from prettytable import PrettyTable

table_open = PrettyTable()
table_closed = PrettyTable()
open_port = []
closed_port = []
info_port = {}
combine_port = {}

def tcp_udp(port):
    tcp_port = {}
    udp_port = {}
    
    # Cek TCP
    try:
        socket.getservbyport(port, "tcp")
        tcp_port[port] = "tcp".upper()
    except OSError:
        pass
    # Cek UDP
    try:
        socket.getservbyport(port, "udp")
        udp_port[port] = "udp".upper()
    except OSError:
        pass
    
    # Cek Combine
    if port in tcp_port and port in udp_port:
        combine_port[port] = 'tcp/udp'.upper()
    elif port in tcp_port:
        combine_port[port] = tcp_port[port]
    elif port in udp_port:
        combine_port[port] = udp_port[port]
    else:
        combine_port[port] = 'unknown'


def name_port(port):
    try:
        service = socket.getservbyport(port)
        info_port[port] = service.upper()
    except:
        info_port[port] = "unknown"


def scan_single(host, port):
    host = socket.gethostbyname(host)
    tcp_udp(port), name_port(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((host, port))
    if result == 0:
        open_port.append(port)
    else:
        closed_port.append(port)


def range_scan(host, port):
    host = socket.gethostbyname(host)
    tcp_udp(port), name_port(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((host, port))
    if result == 0:
        open_port.append(port)
    else:
        closed_port.append(port)


def ip_check(host):
    try: 
        host_alias = socket.gethostbyname_ex(host)
        print(f"Host: {host}")
        print(f"Alias Name: {host_alias[0]}")
        print(f"IP Address: {host_alias[2]}")
    except:
        print("\nMake sure the Domain/IP Address is correct")


print(f"{'='*10} Port Scanner By Ferdy {'='*10}\n")
host = input("Input Host: ")
port = input("Input Port [for range use '-']: ")
os.system("cls")
print(f"{'='*10} Port Scanner By Ferdy {'='*10}\n")
if "-" in port:
    port = port.split("-")
    ip_check(host)
    keep = []
    for i in range(int(port[0]), int(port[1])+1):
        t = threading.Thread(target=range_scan, args=(host, i))
        keep.append(t)
    for x in keep:
        x.start()
    for x in keep:
        x.join()
else:
    ip_check(host)
    scan_single(host, int(port))


print("\nOpen Port:")
if open_port == []:
    print("No open port found")
else:
    open_port.sort()
    table_open.field_names = ["Port", "Protocol", "Service"]
    for open in open_port:
        table_open.add_row([open, combine_port[open] , info_port[open]])
    print(table_open)

print("\nClosed Port:")
if closed_port == []:
    print("No closed port found\n")
else:
    closed_port.sort()
    table_closed.field_names = ["Port", "Protocol", "Service"]
    for close in closed_port:
        table_closed.add_row([close, combine_port[close] , info_port[close]])
    print(table_closed)