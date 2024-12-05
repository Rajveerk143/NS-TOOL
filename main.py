#cspell:disable

from tkinter import messagebox
from tkinter import *
from PIL import Image, ImageTk
import tkinter as tk
import socket
from threading import Thread
import subprocess
import platform
from geopy.geocoders import Nominatim
from tkinter import scrolledtext
from scapy.all import *
import requests

root = Tk()


def login():
    username = e1.get()
    password = e2.get()

    if username == '' and password == '':
        messagebox.showerror('login', 'Username and Password can not be empty')
    elif username == 'NS' and password == 'NS':
        messagebox.showinfo('login', 'Login successful')
        mpage()

    else:
        messagebox.showerror('login', 'Username or Password is incorrect')


def mpage():
    root.destroy()
    mpage = Tk()
    mpage.configure(bg='lightcyan4')
    mpage.state('zoomed')

    photo1 = Image.open('encrDecr.jpg')
    img1 = ImageTk.PhotoImage(photo1)
    bt1 = tk.Button(mpage, text="Encryptor \n /Decrypt-or", relief=RIDGE, command=encryptor, bg='lightcyan4', font=('Helvetica 15 bold'), image= img1, compound=LEFT)
    bt1.image = img1
    bt1.place(rely=0.15, relx=0.15, anchor='center')
    bt1.bind("<Enter>", func=lambda e: bt1.config(
        background='lightcyan3', padx=10, pady=0.1, font=('Areal', 16)))
    # background color on leaving widget
    bt1.bind("<Leave>", func=lambda e: bt1.config(
        background="lightcyan4", padx=0, pady=0, font=('Areal', 15)))


    photo2 = Image.open('wifi_port_sc.png')
    img2 = ImageTk.PhotoImage(photo2)
    bt2 = tk.Button(mpage, text="Wifi-Port \n Scanner", relief=RIDGE, command=portScan, bg='lightcyan4', font=('Helvetica 15 bold'), image=img2, compound=LEFT)
    bt2.image = img2
    bt2.place(rely=0.15, relx=0.50, anchor='center')
    bt2.bind("<Enter>", func=lambda e: bt2.config(background='lightcyan3', padx=10, pady=0.1, font=('Areal', 16)))
    # background color on leaving widget
    bt2.bind("<Leave>", func=lambda e: bt2.config(background="lightcyan4", padx=0, pady=0, font=('Areal', 15)))
    
    
    photo3 = Image.open('icon-white.png')
    img3 = ImageTk.PhotoImage(photo3)
    bt3 = tk.Button(mpage, text="Wifi \n Scanner", relief=RIDGE, command=wifiScan, bg='lightcyan4', font=('Helvetica 15 bold'), image=img3, compound=LEFT)
    bt3.image = img3
    bt3.place(rely=0.15, relx=0.85, anchor='center')
    bt3.bind("<Enter>", func=lambda e: bt3.config( background='lightcyan3', padx=10, pady=0.1, font=('Areal', 16)))
    # background color on leaving widget
    bt3.bind("<Leave>", func=lambda e: bt3.config(background="lightcyan4", padx=0, pady=0, font=('Areal', 15)))
    
    
    photo4 = Image.open('loc.png')
    img4 = ImageTk.PhotoImage(photo4)
    bt4 = tk.Button(mpage, text="Location \n Scanner", relief=RIDGE, command=locate, bg='lightcyan4', font=('Helvetica 15 bold'), image=img4, compound=LEFT)
    bt4.image = img4
    bt4.place(rely=0.40, relx=0.15, anchor='center')
    bt4.bind("<Enter>", func=lambda e: bt4.config( background='lightcyan3', padx=10, pady=0.1, font=('Areal', 16)))
    # 4ackground color on leaving widget
    bt4.bind("<Leave>", func=lambda e: bt4.config(background="lightcyan4", padx=0, pady=0, font=('Areal', 15)))
    
    
    
    photo5 = Image.open('sniff.png')
    img5 = ImageTk.PhotoImage(photo5)
    bt5 = tk.Button(mpage, text="Wifi \n Sniffer", relief=RIDGE, command=wifiSniff, bg='lightcyan4', font=('Helvetica 15 bold'), image=img5, compound=LEFT)
    bt5.image = img5
    bt5.place(rely=0.40, relx=0.50, anchor='center')
    bt5.bind("<Enter>", func=lambda e: bt5.config( background='lightcyan3', padx=10, pady=0.1, font=('Areal', 16)))
    # 5ackground color on leaving widget
    bt5.bind("<Leave>", func=lambda e: bt5.config(background="lightcyan4", padx=0, pady=0, font=('Areal', 15)))

    photo6 = Image.open('loc.png')
    img6 = ImageTk.PhotoImage(photo6)
    bt6 = tk.Button(mpage, text="Location \n Scanner", relief=RIDGE, command=run_firewall_checker, bg='lightcyan4', font=('Helvetica 15 bold'), image=img6, compound=LEFT)
    bt6.image = img6
    bt6.place(rely=0.40, relx=0.85, anchor='center')
    bt6.bind("<Enter>", func=lambda e: bt6.config( background='lightcyan3', padx=10, pady=0.1, font=('Areal', 16)))
    # 6ackground color on leaving widget
    bt6.bind("<Leave>", func=lambda e: bt6.config(background="lightcyan4", padx=0, pady=0, font=('Areal', 15)))
#
# button = Button(win, text="Click Me", font=('Helvetica 15 bold'), image=img, compound=LEFT, command=close_win)
#
# # Pack the button
# button.pack()

def encryptor():
    '''encryptor = Tk()
    encryptor.configure(bg='lightcyan4')
    encryptor.state('zoomed')
'''
    FONT = ("calbri", 20, "bold")

    class CaesarCipherGUI:
        def __init__(self, master):
            master.title("Caesar Cipher GUI")
            self.plaintext = tk.StringVar(master, value="")
            self.ciphertext = tk.StringVar(master, value="")
            self.key = tk.IntVar(master)

            # Plaintext controls
            self.plain_label = tk.Label(master, bg='lightcyan4', text="Plaintext", fg="green", font=FONT).place(relx=0.15, rely=0.15)
            self.plain_entry = tk.Entry(master,
                                        textvariable=self.plaintext, width=50, font=FONT)
            self.plain_entry.place(relx=0.3, rely=0.15)
            self.encrypt_button = tk.Button(master, text="Encrypt",fg='white', bg='forestgreen', relief=RIDGE,
                font=('Areal', 15), bd=2, command=lambda: self.encrypt_callback()).place(relx=0.85, rely=0.15 )
            self.plain_clear = tk.Button(master, text="Clear",fg='white', bg='forestgreen', relief=RIDGE,
                font=('Areal', 15), bd=2, command=lambda: self.clear('plain')).place(relx=0.85, rely=0.25 )

            # Key controls
            self.key_label = tk.Label(master, bg='lightcyan4', text="Key", font=FONT).place(relx=0.15, rely=0.3)
            self.key_entry = tk.Entry(master, textvariable=self.key, width=10, font=FONT)
            self.key_entry.place(relx=0.3, rely=0.3)

            # Ciphertext controls
            self.cipher_label = tk.Label(master, bg='lightcyan4', text="Ciphertext", fg="red", font=FONT).place(relx=0.15, rely=0.5)
            self.cipher_entry = tk.Entry(master, textvariable=self.ciphertext, width=50, font=FONT)
            self.cipher_entry.place(relx=0.3, rely=0.5)
            self.decrypt_button = tk.Button(master, text="Decrypt",fg='white', bg='red', relief=RIDGE,
                font=('Areal', 15), bd=2, command=lambda: self.decrypt_callback()).place(relx=0.85, rely=0.5)
            self.cipher_clear = tk.Button(master, text="Clear",fg='white', bg='red', relief=RIDGE,
                font=('Areal', 15), bd=2, command=lambda: self.clear('cipher')).place(relx=0.85, rely=0.6)

        def clear(self, str_val):
            if str_val == 'cipher':
                self.cipher_entry.delete(0, 'end')
            elif str_val == 'plain':
                self.plain_entry.delete(0, 'end')

        def get_key(self):
            try:
                key_val = self.key.get()
                return key_val
            except tk.TclError:
                pass

        def encrypt_callback(self):
            key = self.get_key()
            ciphertext = encrypt(self.plain_entry.get(), key)
            self.cipher_entry.delete(0, tk.END)
            self.cipher_entry.insert(0, ciphertext)

        def decrypt_callback(self):
            key = self.get_key()
            plaintext = decrypt(self.cipher_entry.get(), key)
            self.plain_entry.delete(0, tk.END)
            self.plain_entry.insert(0, plaintext)

    def encrypt(plaintext, key):
        ciphertext = ""
        for char in plaintext.upper():
            if char.isalpha():
                ciphertext += chr((ord(char) + key - 65) % 26 + 65)
            else:
                ciphertext += char
        return ciphertext

    def decrypt(ciphertext, key):
        plaintext = ""
        for char in ciphertext.upper():
            if char.isalpha():
                plaintext += chr((ord(char) - key - 65) % 26 + 65)
            else:
                plaintext += char
        return plaintext

    if __name__ == "__main__":
        encryptor = tk.Tk()
        encryptor.configure(bg='lightcyan4')
        encryptor.state('zoomed')
        caesar = CaesarCipherGUI(encryptor)
        encryptor.mainloop()

def portScan():
    class NetworkScanner:
        def __init__(self, master):
            self.master = master
            self.master.title("Network Scanner")

            self.host_label = tk.Label(master, text="Enter Host/IP:")
            self.host_label.pack()

            self.host_entry = tk.Entry(master)
            self.host_entry.pack()

            self.scan_button = tk.Button(master, text="Scan Ports", command=self.scan_ports)
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
        wifiScan = tk.Tk()
        wifiScan.configure(bg='lightcyan4')
        wifiScan.state('zoomed')
        sc = NetworkScanner(wifiScan)
        wifiScan.mainloop()


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
                    xml_template = f'''<?xml version="1.0"?>
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
                    </WLANProfile>'''
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


def locate():
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


def wifiSniff():
    class WiFiSnifferApp:
        def __init__(self, master):
            self.master = master
            self.master.title("WiFi Sniffer")

            self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
            self.start_button.pack()

            self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
            self.stop_button.pack()

            self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=20)
            self.text_area.pack()

            self.sniffing = False

        def start_sniffing(self):
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            # Start sniffing in a separate thread to avoid blocking the UI
            self.sniff_thread = Thread(target=self.sniff_packets)
            self.sniff_thread.start()

        def stop_sniffing(self):
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

        def sniff_packets(self):
            sniff(prn=self.display_packet, stop_filter=self.stop_filter)

        def display_packet(self, packet):
            if self.sniffing:
                packet_info = f"{packet.summary()}\n"
                self.text_area.insert(tk.END, packet_info)
                self.text_area.see(tk.END)

        def stop_filter(self, packet):
            return not self.sniffing

    # Initialize Tkinter root and WiFiSnifferApp
    root = tk.Tk()
    app = WiFiSnifferApp(root)
    root.mainloop()

def run_firewall_checker():
    # Function to check the site
    def check_site(url):
        timeout = 5  # seconds
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                return f"Successfully connected to {url}. Firewall does not appear to be blocking it."
            else:
                return f"Received response code {response.status_code}. Firewall might be blocking the site."
        except requests.exceptions.RequestException as e:
            return f"Error connecting to {url}. Possible firewall block or network issue.\n{e}"

def run_firewall_checker():
    # Function to check the site
    def check_site(url):
        timeout = 5  # seconds
        try:
            # Attempt to make a basic GET request to check accessibility
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                return f"Successfully connected to {url}. Firewall does not appear to be blocking HTTP access."
            else:
                return f"Received HTTP response code {response.status_code}. This might indicate a firewall block or site issue."
        except requests.exceptions.RequestException as e:
            return f"Error connecting to {url}. This could be due to a firewall block or other network issues.\nDetails: {e}"

    # Function to handle the Check button click
    def check_firewall():
        url = url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return
        
        # Start a separate thread to handle the site check so the UI remains responsive
        def worker():
            result = check_site(url)
            messagebox.showinfo("Result", result)
        
        # Use threading to avoid blocking the main GUI thread
        threading.Thread(target=worker).start()

    # Set up the Tkinter application
    root = tk.Tk()
    root.title("Firewall Checker")

    # Create and place the URL entry widget
    tk.Label(root, text="Enter URL to check:").pack(pady=10)
    url_entry = tk.Entry(root, width=50)
    url_entry.pack(pady=5)

    # Create and place the Check button
    check_button = tk.Button(root, text="Check Firewall", command=check_firewall)
    check_button.pack(pady=20)

    # Run the Tkinter event loop
    root.mainloop()

    

# setting attribute
root.state('zoomed')

w = root.winfo_screenwidth()
h = root.winfo_screenheight()

root.title("NS TOOL")
root.configure(bg='black')

photo = Image.open('a1.jpg')
img = ImageTk.PhotoImage(photo)
lb = tk.Label(root, image=img)
lb.image = img
lb.place(rely=0.5, relx=0.25, anchor='center')

label = Label(root, text='Login Page', bg='black', fg='white', font=('Lucida Fax', 50))
label.place(relx=0.7, rely=0.2, anchor='center')

uname = Label(root, text='UserName :', bg='black', fg='white', font=('Lucida Fax', 20))
uname.place(relx=0.6, rely=0.35, anchor='center')

pas = Label(root, text='Password :', bg='black', fg='white', font=('Lucida Fax', 20))
pas.place(relx=0.6, rely=0.45, anchor='center')

global e1
e1 = Entry(root, font=('Areal', 20))
e1.place(relx=0.75, rely=0.35, anchor='center')

global e2
e2 = Entry(root, font=('Areal', 20), show='*')
e2.place(relx=0.75, rely=0.45, anchor='center')

button = Button(root, text='Login', command=login, padx=50, pady=5, fg='white', bg='forestgreen', relief=RIDGE,
                font=('Areal', 15), bd=2)
button.place(relx=0.70, rely=0.55, anchor='center')
# adjusting background of the widget
# background on entering widget
button.bind("<Enter>", func=lambda e: button.config(
    background='green', padx=52, pady=5.5, font=('Areal', 16)))

# background color on leaving widget
button.bind("<Leave>", func=lambda e: button.config(
    background="forestgreen", padx=50, pady=5, font=('Areal', 15)))

root.mainloop()
