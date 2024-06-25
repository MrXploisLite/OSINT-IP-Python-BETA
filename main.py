import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests
import socket
import subprocess
import nmap
from scapy.all import sniff, conf

class OSINTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT & Spy Tools")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.create_widgets()
    
    def create_widgets(self):
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        
        # IP Geolocation
        self.create_entry_button_pair("Enter IP address to geolocate:", 0, self.geolocate_ip)
        
        # Reverse DNS Lookup
        self.create_entry_button_pair("Enter IP address for reverse DNS lookup:", 1, self.reverse_dns)
        
        # Trace Route
        self.create_entry_button_pair("Enter target hostname or IP to trace route:", 2, self.trace_route)
        
        # Scan Ports
        self.create_entry_button_pair("Enter target IP address to scan ports:", 3, self.scan_ports)
        
        # Sniff Packets
        self.create_entry_button_pair("Enter network interface to sniff packets:", 4, self.sniff_packets)
        
        # DNS Lookup
        self.create_entry_button_pair("Enter domain name for DNS lookup:", 5, self.dns_lookup)
        
        # WHOIS Lookup
        self.create_entry_button_pair("Enter IP address for WHOIS lookup:", 6, self.whois_lookup)
        
        # Output Display
        self.output_text = tk.Text(self.main_frame, height=10, width=80)
        self.output_text.grid(row=7, column=0, columnspan=3, pady=10)
        
        # Status Bar
        self.status_bar = ttk.Label(self.main_frame, text="", anchor="center", padding=(0, 10))
        self.status_bar.grid(row=8, column=0, columnspan=3, sticky="ew")
        
        # Configure grid weights
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.columnconfigure(2, weight=1)
        self.main_frame.rowconfigure(7, weight=1)
        
    def create_entry_button_pair(self, label_text, row, command):
        ttk.Label(self.main_frame, text=label_text).grid(row=row, column=0, sticky="w")
        entry = ttk.Entry(self.main_frame, width=30)
        entry.grid(row=row, column=1, padx=10)
        ttk.Button(self.main_frame, text=label_text.split(" ")[1], command=lambda e=entry: command(e)).grid(row=row, column=2, padx=10)
    
    def update_status(self, message):
        self.status_bar.config(text=message)
    
    def update_output(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
    
    def clear_output(self):
        self.output_text.delete("1.0", tk.END)
    
    def geolocate_ip(self, entry):
        ip_address = entry.get().strip()
        if not ip_address:
            messagebox.showwarning("Warning", "Please enter an IP address.")
            return
        
        threading.Thread(target=self.perform_geolocation, args=(ip_address,)).start()
    
    def perform_geolocation(self, ip_address):
        self.clear_output()
        self.update_status(f"Geolocating IP: {ip_address}")
        
        try:
            token = "f4e33dbb3be677"
            url = f"https://ipinfo.io/{ip_address}/json?token={token}"
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                info = (
                    f"IP: {data.get('ip', 'N/A')}\n"
                    f"Hostname: {data.get('hostname', 'N/A')}\n"
                    f"City: {data.get('city', 'N/A')}\n"
                    f"Region: {data.get('region', 'N/A')}\n"
                    f"Country: {data.get('country', 'N/A')}\n"
                    f"Location: {data.get('loc', 'N/A')}\n"
                    f"Organization: {data.get('org', 'N/A')}\n"
                    f"Postal: {data.get('postal', 'N/A')}\n"
                    f"Timezone: {data.get('timezone', 'N/A')}\n"
                    f"Readme: {data.get('readme', 'N/A')}"
                )
                self.update_output(info)
                self.update_status("IP geolocation complete.")
            else:
                self.update_output("Failed to fetch IP information.")
                self.update_status("IP geolocation failed.")
        except Exception as e:
            self.update_output(f"Error during IP geolocation: {str(e)}")
            self.update_status("IP geolocation failed.")
    
    def reverse_dns(self, entry):
        ip_address = entry.get().strip()
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
    
    def trace_route(self, entry):
        target = entry.get().strip()
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
    
    def scan_ports(self, entry):
        target = entry.get().strip()
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
    
    def sniff_packets(self, entry):
        interface = entry.get().strip()
        if not interface:
            messagebox.showwarning("Warning", "Please enter a network interface.")
            return

        if conf.L2listen:
            threading.Thread(target=self.perform_sniff_packets, args=(interface,)).start()
        else:
            self.update_output("No libpcap provider available! pcap won't be used.")
            self.update_status("Packet sniffing failed.")
    
    def perform_sniff_packets(self, interface):
        self.clear_output()
        self.update_status(f"Sniffing packets on interface: {interface}")
        
        try:
            sniff(iface=interface, prn=self.process_sniffed_packet)
            self.update_status("Packet sniffing complete.")
        except Exception as e:
            self.update_output(f"Error during packet sniffing: {str(e)}")
            self.update_status("Packet sniffing failed.")
    
    def process_sniffed_packet(self, packet):
        self.update_output(f"Sniffed Packet: {packet.summary()}")
    
    def dns_lookup(self, entry):
        domain = entry.get().strip()
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
    
    def whois_lookup(self, entry):
        ip_address = entry.get().strip()
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
        except FileNotFoundError as e:
            self.update_output(f"WHOIS command not found: {str(e)}. Please ensure whois is installed and added to PATH.")
            self.update_status("WHOIS lookup failed.")

def main():
    root = tk.Tk()
    app = OSINTApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
