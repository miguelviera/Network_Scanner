import scapy.all as scapy
import argparse

# Funtion to make program work for python3 or any other previous version
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

# Funtion to scan network
def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether()
    broadcast.dst = "ff:ff:ff:ff:ff:ff"
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

# Funtion to print the results after scanning the network
def print_result(results_list):
    print("IP\t\t\tMAC Address\n**********************************************")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# Calling the functions 
options = get_arguments()
print_result(scan_network("192.168.189.2/24"))