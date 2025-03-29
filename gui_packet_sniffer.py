import tkinter as tk
from tkinter import scrolledtext
import threading
import os
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS

# Log file setup
LOG_FILE = "packets.log"

# Function to log packets to file
def log_packet(packet_info):
    with open(LOG_FILE, "a") as log:
        log.write(packet_info + "\n")

# Function to process packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "OTHER"
        port_src, port_dst = "N/A", "N/A"

        # Identify Protocols
        if packet.haslayer(TCP):
            protocol = "TCP"
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        
        # HTTP Filter
        if filter_var.get() == "HTTP" and port_dst != 80:
            return
        # DNS Filter
        if filter_var.get() == "DNS" and not packet.haslayer(DNS):
            return
        # TCP Filter
        if filter_var.get() == "TCP" and not packet.haslayer(TCP):
            return
        # UDP Filter
        if filter_var.get() == "UDP" and not packet.haslayer(UDP):
            return

        packet_info = f"[{protocol}] {ip_src}:{port_src} → {ip_dst}:{port_dst}"
        log_packet(packet_info)

        # Display packet in GUI
        text_output.insert(tk.END, packet_info + "\n")
        text_output.yview(tk.END)

# Function to start packet sniffing in a separate thread
def start_sniffing():
    sniff(prn=packet_callback, store=False)

def start_sniffer_thread():
    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()

# Function to clear logs
def clear_logs():
    if os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()
    text_output.delete(1.0, tk.END)

# GUI Setup
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("600x400")

# Filter Options
filter_var = tk.StringVar(value="All")
tk.Label(root, text="Filter:").pack()
filter_menu = tk.OptionMenu(root, filter_var, "All", "HTTP", "DNS", "TCP", "UDP", "ICMP")
filter_menu.pack()

# Start Button
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffer_thread)
start_button.pack()

# Clear Logs Button
clear_button = tk.Button(root, text="Clear Logs", command=clear_logs)
clear_button.pack()

# Text Output
text_output = scrolledtext.ScrolledText(root, width=70, height=15)
text_output.pack()

# Run GUI
root.mainloop()

