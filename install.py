#!/usr/bin/python
from colorama import Fore,Back,Style
import os,time

print(Style.BRIGHT)
print(Fore.GREEN + "\n[+] Installing Dependencies...\n")
os.system("pip install -r resources.txt")
print(Fore.GREEN + "\n[+] Installing APKWASH...\n")
os.system("git clone https://github.com/jbreed/apkwash.git")
print(Fore.GREEN + "[!] APKWASH Installed successfully!")
time.sleep(1)
print(Fore.GREEN + "[!] Installing Terminator")
time.sleep(1)
os.system("apt-get install terminator")
time.sleep(1)
print(Fore.GREEN + "[+] Creating directorys")
os.system("mkdir logs")
print(Fore.GREEN + "[+] Done..")

