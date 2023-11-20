from scapy.all import *
import os
import tkinter as tk
from tkinter import scrolledtext

class WiFiScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Scanner")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=20)
        self.text_area.pack(padx=10, pady=10)

        self.start_button = tk.Button(root, text="Start WiFi Scan", command=self.start_wifi_scan)
        self.start_button.pack(pady=10)

    def wifi_scan(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:  # 0: Management frame, 8: Beacon frame
                result = f"SSID: {pkt.info.decode()}, BSSID: {pkt.addr2}, Signal Strength: {pkt.dBm_AntSignal}\n"
                self.text_area.insert(tk.END, result)

    def start_wifi_scan(self):
        self.text_area.delete('1.0', tk.END)  # Clear previous results
        # Set the interface in monitor mode
        os.system("sudo ifconfig wlan0 down")
        os.system("sudo iwconfig wlan0 mode monitor")
        os.system("sudo ifconfig wlan0 up")

        # Start sniffing for WiFi packets
        sniff(prn=self.wifi_scan, iface="wlan0", store=0)

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiScannerGUI(root)
    root.mainloop()
