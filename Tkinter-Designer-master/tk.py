import tkinter as tk
from geopy.geocoders import Nominatim

class LocationTracker:
    def __init__(self, master):
        self.master = master
        self.master.title("Location Tracker")

        self.geolocator = Nominatim(user_agent="location_tracker")

        self.label = tk.Label(master, text="Enter location:")
        self.label.pack()

        self.entry = tk.Entry(master)
        self.entry.pack()

        self.button = tk.Button(master, text="Track Location", command=self.track_location)
        self.button.pack()

        self.result_label = tk.Label(master, text="")
        self.result_label.pack()

    def track_location(self):
        location_name = self.entry.get()
        if location_name:
            location = self.geolocator.geocode(location_name)
            if location:
                latitude, longitude = location.latitude, location.longitude
                result_text = f"Latitude: {latitude}, Longitude: {longitude}"
                self.result_label.config(text=result_text)
            else:
                self.result_label.config(text="Location not found.")
        else:
            self.result_label.config(text="Please enter a location.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LocationTracker(root)
    root.mainloop()

'''
import tkinter as tk
import platform
import subprocess

def wifiScan():
    class WiFiTool:
        def __init__(self, master):
            self.master = master
            self.master.title("Wi-Fi Scanner")

            self.scan_button = tk.Button(master, text="Scan Wi-Fi", command=self.scan_wifi)
            self.scan_button.pack()

            self.networks_text = tk.Text(master, height=15, width=50)
            self.networks_text.pack()

            self.connect_button = tk.Button(master, text="Connect Wi-Fi", command=self.connect_wifi)
            self.connect_button.pack()

            self.ssid_label = tk.Label(master, text="Enter SSID:")
            self.ssid_label.pack()

            self.ssid_entry = tk.Entry(master)
            self.ssid_entry.pack()

            self.password_label = tk.Label(master, text="Enter Password:")
            self.password_label.pack()

            self.password_entry = tk.Entry(master, show='*')
            self.password_entry.pack()

        def scan_wifi(self):
            if platform.system() == "Windows":
                result = subprocess.run(["netsh", "wlan", "show", "network"], capture_output=True, text=True)
                networks_info = result.stdout
            elif platform.system() == "Linux":
                result = subprocess.run(["nmcli", "device", "wifi", "list"], capture_output=True, text=True)
                networks_info = result.stdout
            else:
                networks_info = "Unsupported platform"

            self.networks_text.delete("1.0", tk.END)
            self.networks_text.insert(tk.END, networks_info)

        def connect_wifi(self):
            ssid = self.ssid_entry.get()
            password = self.password_entry.get()

            if not ssid:
                self.networks_text.insert(tk.END, "Please enter an SSID.\n")
                return

            if platform.system() == "Windows":
                command = f'netsh wlan connect name="{ssid}"'
                if password:
                    command = f'netsh wlan add profile filename="temp.xml" interface="Wi-Fi" user=current'
                    xml_template = f''' '''<?xml version="1.0"?>
                    <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
                        <name>{ssid}</name>
                        <SSIDConfig>
                            <SSID>
                                <name>{ssid}</name>
                            </SSID>
                        </SSIDConfig>
                        <connectionType>ESS</connectionType>
                        <connectionMode>auto</connectionMode>
                        <MSM>
                            <security>
                                <authEncryption>
                                    <authentication>WPA2PSK</authentication>
                                    <encryption>AES</encryption>
                                    <useOneX>false</useOneX>
                                </authEncryption>
                                <sharedKey>
                                    <keyType>passPhrase</keyType>
                                    <protected>false</protected>
                                    <keyMaterial>{password}</keyMaterial>
                                </sharedKey>
                            </security>
                        </MSM>
                    </WLANProfile>''' '''
                    with open("temp.xml", "w") as file:
                        file.write(xml_template)
            elif platform.system() == "Linux":
                command = f'nmcli dev wifi connect "{ssid}" password "{password}"'
            else:
                self.networks_text.insert(tk.END, "Unsupported platform.\n")
                return

            try:
                subprocess.run(command, shell=True, check=True)
                self.networks_text.insert(tk.END, f"Connected to {ssid}.\n")
            except subprocess.CalledProcessError as e:
                self.networks_text.insert(tk.END, f"Failed to connect to {ssid}.\n")

    if __name__ == "__main__":
        root = tk.Tk()
        app = WiFiTool(root)
        root.mainloop()
'''
'''
import tkinter as tk
from tkinter import ttk
import socket
from threading import Thread

class NetworkScanner:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Scanner")

        self.host_label = ttk.Label(master, text="Enter Host/IP:")
        self.host_label.pack()

        self.host_entry = ttk.Entry(master)
        self.host_entry.pack()

        self.scan_button = ttk.Button(master, text="Scan Ports", command=self.scan_ports)
        self.scan_button.pack()

        self.result_text = tk.Text(master, height=10, width=40)
        self.result_text.pack()

    def scan_ports(self):
        self.result_text.delete("1.0", tk.END)

        host = self.host_entry.get()
        if not host:
            self.result_text.insert(tk.END, "Please enter a valid Host/IP.")
            return

        self.result_text.insert(tk.END, f"Scanning ports on {host}...\n")

        for port in range(1, 1025):
            t = Thread(target=self.check_port, args=(host, port))
            t.start()

    def check_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                self.result_text.insert(tk.END, f"Port {port} is open.\n")
            sock.close()
        except Exception as e:
            pass

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScanner(root)
    root.mainloop()

'''
