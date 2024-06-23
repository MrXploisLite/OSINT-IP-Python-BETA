import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests
import socket
import subprocess
import nmap
import scapy.all as scapy
from urllib.parse import urlparse

class OSINTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT & Spy Tools")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Choose a theme ('clam', 'alt', 'default', 'classic')

        self.create_widgets()
    
    def create_widgets(self):
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        
        # IP Geolocation
        ttk.Label(self.main_frame, text="Enter IP address to geolocate:").grid(row=0, column=0, sticky="w")
        self.ip_address_entry = ttk.Entry(self.main_frame, width=30)
        self.ip_address_entry.grid(row=0, column=1, padx=10)
        ttk.Button(self.main_frame, text="Geolocate IP", command=self.geolocate_ip).grid(row=0, column=2, padx=10)
        
        # Reverse DNS Lookup
        ttk.Label(self.main_frame, text="Enter IP address for reverse DNS lookup:").grid(row=1, column=0, sticky="w")
        self.reverse_dns_entry = ttk.Entry(self.main_frame, width=30)
        self.reverse_dns_entry.grid(row=1, column=1, padx=10)
        ttk.Button(self.main_frame, text="Reverse DNS Lookup", command=self.reverse_dns).grid(row=1, column=2, padx=10)
        
        # Trace Route
        ttk.Label(self.main_frame, text="Enter target hostname or IP to trace route:").grid(row=2, column=0, sticky="w")
        self.trace_route_entry = ttk.Entry(self.main_frame, width=30)
        self.trace_route_entry.grid(row=2, column=1, padx=10)
        ttk.Button(self.main_frame, text="Trace Route", command=self.trace_route).grid(row=2, column=2, padx=10)
        
        # Scan Ports
        ttk.Label(self.main_frame, text="Enter target IP address to scan ports:").grid(row=3, column=0, sticky="w")
        self.scan_ports_entry = ttk.Entry(self.main_frame, width=30)
        self.scan_ports_entry.grid(row=3, column=1, padx=10)
        ttk.Button(self.main_frame, text="Scan Ports", command=self.scan_ports).grid(row=3, column=2, padx=10)
        
        # Sniff Packets
        ttk.Label(self.main_frame, text="Enter network interface to sniff packets:").grid(row=4, column=0, sticky="w")
        self.sniff_interface_entry = ttk.Entry(self.main_frame, width=30)
        self.sniff_interface_entry.grid(row=4, column=1, padx=10)
        ttk.Button(self.main_frame, text="Sniff Packets", command=self.sniff_packets).grid(row=4, column=2, padx=10)
        
        # DNS Lookup
        ttk.Label(self.main_frame, text="Enter domain name for DNS lookup:").grid(row=5, column=0, sticky="w")
        self.dns_domain_entry = ttk.Entry(self.main_frame, width=30)
        self.dns_domain_entry.grid(row=5, column=1, padx=10)
        ttk.Button(self.main_frame, text="DNS Lookup", command=self.dns_lookup).grid(row=5, column=2, padx=10)
        
        # WHOIS Lookup
        ttk.Label(self.main_frame, text="Enter IP address for WHOIS lookup:").grid(row=6, column=0, sticky="w")
        self.whois_ip_entry = ttk.Entry(self.main_frame, width=30)
        self.whois_ip_entry.grid(row=6, column=1, padx=10)
        ttk.Button(self.main_frame, text="WHOIS Lookup", command=self.whois_lookup).grid(row=6, column=2, padx=10)
        
        # GeoIP Lookup
        ttk.Label(self.main_frame, text="Enter IP address for GeoIP lookup:").grid(row=7, column=0, sticky="w")
        self.geoip_ip_entry = ttk.Entry(self.main_frame, width=30)
        self.geoip_ip_entry.grid(row=7, column=1, padx=10)
        ttk.Button(self.main_frame, text="GeoIP Lookup", command=self.geoip_lookup).grid(row=7, column=2, padx=10)
        
        # Output Display
        self.output_text = tk.Text(self.main_frame, height=10, width=80)
        self.output_text.grid(row=8, column=0, columnspan=3, pady=10)
        
        # Status Bar
        self.status_bar = ttk.Label(self.main_frame, text="", anchor="center", padding=(0, 10))
        self.status_bar.grid(row=9, column=0, columnspan=3, sticky="ew")
        
        # Configure grid weights
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.columnconfigure(2, weight=1)
        self.main_frame.rowconfigure(8, weight=1)
        
    def update_status(self, message):
        self.status_bar.config(text=message)
    
    def update_output(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
    
    def clear_output(self):
        self.output_text.delete("1.0", tk.END)
    
    def geolocate_ip(self):
        ip_address = self.ip_address_entry.get().strip()
        if not ip_address:
            messagebox.showwarning("Warning", "Please enter an IP address.")
            return
        
        threading.Thread(target=self.perform_geolocation, args=(ip_address,)).start()
    
    def perform_geolocation(self, ip_address):
        self.clear_output()
        self.update_status(f"Geolocating IP: {ip_address}")
        
        try:
            url = f"https://ipinfo.io/{ip_address}/json"
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                info = (
                    f"IP: {data['ip']}\n"
                    f"City: {data['city']}\n"
                    f"Region: {data['region']}\n"
                    f"Country: {data['country']}\n"
                    f"Location: {data['loc']}\n"
                    f"Organization: {data['org']}"
                )
                self.update_output(info)
                self.update_status("IP geolocation complete.")
            else:
                self.update_output("Failed to fetch IP information.")
                self.update_status("IP geolocation failed.")
        except Exception as e:
            self.update_output(f"Error during IP geolocation: {str(e)}")
            self.update_status("IP geolocation failed.")
    
    def reverse_dns(self):
        ip_address = self.reverse_dns_entry.get().strip()
        if not ip_address:
            messagebox.showwarning("Warning", "Please enter an IP address.")
            return
        
        threading.Thread(target=self.perform_reverse_dns, args=(ip_address,)).start()
    
    def perform_reverse_dns(self, ip_address):
        self.clear_output()
        self.update_status(f"Performing reverse DNS lookup for: {ip_address}")
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            self.update_output(f"Reverse DNS Lookup: {hostname}")
            self.update_status("Reverse DNS lookup complete.")
        except socket.herror:
            self.update_output(f"Reverse DNS Lookup not available for {ip_address}")
            self.update_status("Reverse DNS lookup failed.")
        except Exception as e:
            self.update_output(f"Error during reverse DNS lookup: {str(e)}")
            self.update_status("Reverse DNS lookup failed.")
    
    def trace_route(self):
        target = self.trace_route_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please enter a target hostname or IP.")
            return
        
        threading.Thread(target=self.perform_trace_route, args=(target,)).start()
    
    def perform_trace_route(self, target):
        self.clear_output()
        self.update_status(f"Tracing route to: {target}")
        
        try:
            process = subprocess.Popen(["traceroute", target], stdout=subprocess.PIPE)
            output, _ = process.communicate()
            self.update_output(output.decode())
            self.update_status("Trace route complete.")
        except Exception as e:
            self.update_output(f"Error during trace route: {str(e)}")
            self.update_status("Trace route failed.")
    
    def scan_ports(self):
        target = self.scan_ports_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please enter a target IP address.")
            return
        
        threading.Thread(target=self.perform_scan_ports, args=(target,)).start()
    
    def perform_scan_ports(self, target):
        self.clear_output()
        self.update_status(f"Scanning ports on: {target}")
        
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments='-p 1-1000')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        self.update_output(f"Port {port}/{proto}: {state}")
            
            self.update_status("Port scan complete.")
        except Exception as e:
            self.update_output(f"Error during port scan: {str(e)}")
            self.update_status("Port scan failed.")
    
    def sniff_packets(self):
        interface = self.sniff_interface_entry.get().strip()
        if not interface:
            messagebox.showwarning("Warning", "Please enter a network interface.")
            return
        
        threading.Thread(target=self.perform_sniff_packets, args=(interface,)).start()
    
    def perform_sniff_packets(self, interface):
        self.clear_output()
        self.update_status(f"Sniffing packets on interface: {interface}")
        
        try:
            scapy.sniff(iface=interface, prn=self.process_sniffed_packet)
            self.update_status("Packet sniffing complete.")
        except Exception as e:
            self.update_output(f"Error during packet sniffing: {str(e)}")
            self.update_status("Packet sniffing failed.")
    
    def process_sniffed_packet(self, packet):
        self.update_output(f"Sniffed Packet: {packet.summary()}")
    
    def dns_lookup(self):
        domain = self.dns_domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Warning", "Please enter a domain name.")
            return
        
        threading.Thread(target=self.perform_dns_lookup, args=(domain,)).start()
    
    def perform_dns_lookup(self, domain):
        self.clear_output()
        self.update_status(f"Performing DNS lookup for: {domain}")
        
        try:
            ip_addresses = socket.gethostbyname_ex(domain)
            self.update_output(f"DNS Lookup for {domain}: {', '.join(ip_addresses[2])}")
            self.update_status("DNS lookup complete.")
        except Exception as e:
            self.update_output(f"Error during DNS lookup: {str(e)}")
            self.update_status("DNS lookup failed.")
    
    def whois_lookup(self):
        ip_address = self.whois_ip_entry.get().strip()
        if not ip_address:
            messagebox.showwarning("Warning", "Please enter an IP address.")
            return
        
        threading.Thread(target=self.perform_whois_lookup, args=(ip_address,)).start()
    
    def perform_whois_lookup(self, ip_address):
        self.clear_output()
        self.update_status(f"Performing WHOIS lookup for: {ip_address}")
        
        try:
            whois_info = subprocess.check_output(["whois", ip_address], universal_newlines=True)
            self.update_output(f"WHOIS Lookup for {ip_address}:\n{whois_info}")
            self.update_status("WHOIS lookup complete.")
        except subprocess.CalledProcessError as e:
            self.update_output(f"Error during WHOIS lookup: {str(e)}")
            self.update_status("WHOIS lookup failed.")
    
    def geoip_lookup(self):
        ip_address = self.geoip_ip_entry.get().strip()
        if not ip_address:
            messagebox.showwarning("Warning", "Please enter an IP address.")
            return
        
        threading.Thread(target=self.perform_geoip_lookup, args=(ip_address,)).start()
    
    def perform_geoip_lookup(self, ip_address):
        self.clear_output()
        self.update_status(f"Performing GeoIP lookup for: {ip_address}")
        
        try:
            url = f"https://ipinfo.io/{ip_address}/json"
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                info = (
                    f"IP: {data['ip']}\n"
                    f"City: {data['city']}\n"
                    f"Region: {data['region']}\n"
                    f"Country: {data['country']}\n"
                    f"Location: {data['loc']}\n"
                    f"Organization: {data['org']}"
                )
                self.update_output(info)
                self.update_status("GeoIP lookup complete.")
            else:
                self.update_output("Failed to fetch GeoIP information.")
                self.update_status("GeoIP lookup failed.")
        except Exception as e:
            self.update_output(f"Error during GeoIP lookup: {str(e)}")
            self.update_status("GeoIP lookup failed.")

def main():
    root = tk.Tk()
    app = OSINTApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()