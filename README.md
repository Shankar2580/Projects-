Packet Sniffer GUI

A simple packet sniffer built using **Python, Tkinter, and Scapy**. This tool captures network packets and provides a GUI to display them in real-time with filtering options.

Features
- Captures network packets in real-time.
- Supports filtering by **protocols**: HTTP, DNS, TCP, UDP, and ICMP.
- Displays source and destination IP addresses and ports.
- Logs captured packets to a **log file (`packets.log`)**.
- Provides a **GUI** with a scrollable text box for viewing packets.
- Allows clearing logs directly from the GUI.

Prerequisites
- **Python** (≥3.6)
- **pip** (Python package manager)
- **Scapy** (for packet sniffing)
- **Tkinter** (GUI module, comes pre-installed with Python)

To install missing dependencies, run:

pip install scapy

### **How to Run**
1. **Clone the repository** (or download the script manually):
   ```bash
   git clone https://github.com/yourusername/PacketSnifferGUI.git
   cd PacketSnifferGUI
   ```
2. **Run the script** with administrator/root privileges:
   ```bash
   sudo python3 packet_sniffer.py
   ```
   *(Packet sniffing requires root/admin access.)*

---

How It Works*
- Click the **"Start Sniffing"** button to begin capturing packets.
- Select a **filter option** (e.g., DNS, TCP) to capture specific traffic.
- View real-time logs in the **scrollable text box**.
- Click **"Clear Logs"** to erase the log file.





### **Screenshots**
![image](https://github.com/user-attachments/assets/008fdf4f-5c1d-4092-be16-9d2409ba1873)
![image](https://github.com/user-attachments/assets/e81a3020-1084-49b5-83cd-13900bdaece2)


