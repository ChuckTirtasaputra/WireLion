# Chuck Tirtasaputra and Laura Benner
# Packet Sniffing

import socket
import threading
import tkinter as tk
from tkinter import ttk
import webbrowser
from scapy.all import *
from tkinter import messagebox
import json

with open('ip.json', 'r') as f:
    data = json.load(f)

blacklist = data["ip_addresses"]

hacked = []

# Custom function to show an alert with a larger skull and crossbones symbol
def show_alert(ip):    
    if ip in hacked:
        return
    else:
        hacked.append(ip)
        alert_window = tk.Toplevel(window)
        alert_window.title("Alert")
        
        # Set the size of the window
        alert_window.geometry("300x150")
        
        # Create a label with the skull and crossbones symbol and bigger font
        label = tk.Label(alert_window, text=chr(9760), font=("Arial", 48), fg="red")
        label.pack(pady=20)

        # Create a label for the alert message
        message = tk.Label(alert_window, text="Blacklisted IP detected!", font=("Arial", 16))
        message.pack(pady=10)
        
        # Create a close button
        close_button = tk.Button(alert_window, text="Close", command=alert_window.destroy)
        close_button.pack(pady=10)

        # Make sure the alert window is on top of other windows
        alert_window.transient(window)
        alert_window.grab_set()
        alert_window.focus()
    

# Global variable to control packet capture
capturing = False

# IP lookup function
def ip_to_dns(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "No DNS record found"

# Function to capture and process packets
def capture_packets(interface="en0"):  # Change interface here based on get_if_list()
    global capturing
    while capturing:
        sniff(iface=interface, prn=process_packet, store=False, timeout=1)  # Add timeout

# Function to process each packet
def process_packet(packet):
    if packet.haslayer(IP):
        ip_address = packet[IP].src  # Source IP
        dns_name = ip_to_dns(ip_address)  # DNS name of IP Address

        if packet.haslayer(TCP):
            if dns_name == "No DNS record found":
                data = (len(alldata) + 1, packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, "Private Organization")
            else:
                url = "https://www.abuseipdb.com/check/" + str(packet[IP].src)
                data = (len(alldata) + 1, packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, url)
        else:  # UDP Packets
            if dns_name == "No DNS record found":
                data = (len(alldata) + 1, packet[IP].src, packet[IP].dst, "NULL", "NULL", "Private Organization")
            else:
                url = "https://www.abuseipdb.com/check/" + str(packet[IP].src)
                data = (len(alldata) + 1, packet[IP].src, packet[IP].dst, "NULL", "NULL", url)

        alldata.append(data)

        # Insert new row into the table
        row_id = table.insert("", tk.END, values=data)

        # Check if the source IP is in the blacklist
        if packet[IP].src in blacklist:
            # Apply a tag to highlight the row
            table.item(row_id, tags=("blacklist",))
            show_alert(packet[IP].src)

# Function to start capturing packets
def start_capture():
    global capturing

    # Clear the table
    for row in table.get_children():
        table.delete(row)

    alldata.clear()
    capturing = True
    thread = threading.Thread(target=capture_packets, args=("en0",))  # Use the correct interface here
    thread.daemon = True  # Allows the thread to be killed when the main program exits
    thread.start()

# Function to stop capturing packets
def stop_capture():
    global capturing
    capturing = False

# Create the main window
window = tk.Tk()
window.title("WireLion")

# Sample data for the table
alldata = []

# Frame to contain search bar and buttons
search_frame = tk.Frame(window)
search_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

# Create a start button
start_button = tk.Button(search_frame, text="Start", bg="green", command=start_capture)
start_button.pack(side=tk.LEFT, padx=5)

# Create a stop button
stop_button = tk.Button(search_frame, text="Stop", bg="red", command=stop_capture)
stop_button.pack(side=tk.LEFT, padx=5)

# Create a label and search entry
search_label = tk.Label(search_frame, text="Search:")
search_label.pack(side=tk.LEFT)
search_entry = tk.Entry(search_frame)
search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

# Create a search button
search_button = tk.Button(search_frame, text="Search", command=lambda: search())
search_button.pack(side=tk.RIGHT, padx=5)

# Function to filter the table based on the search input
def search():
    query = search_entry.get().lower()  # Get the search query and convert to lowercase
    for row in table.get_children():
        table.delete(row)  # Clear current table rows

    for row in alldata:
        # Check if any of the IPs or ports match the query
        if (query in str(row[1]).lower() or query in str(row[2]).lower() or
            (len(row) > 3 and (query in str(row[3]) or query in str(row[4]) or query in str(row[5])))):
            table.insert("", tk.END, values=row)  # Insert matching rows

# Create the Treeview widget (table)
table = ttk.Treeview(window, columns=("#", "Src IP", "Dst IP", "Src Port", "Dst Port", "DNS Lookup"), show="headings")

# Column Width Information
table.column("#", anchor="center", stretch="no", width=50)
table.column("Src Port", anchor="w", stretch="no", width=100)
table.column("Dst Port", anchor="w", stretch="no", width=100)

# Headings
table.heading("#", text="#")
table.heading("Src IP", text="Src IP")
table.heading("Dst IP", text="Dst IP")
table.heading("Src Port", text="Src Port")
table.heading("Dst Port", text="Dst Port")
table.heading("DNS Lookup", text="DNS Lookup")

# Pack the table to display it
table.pack(fill=tk.BOTH, expand=True)

# Add tag configurations for highlighting blacklist rows
table.tag_configure("blacklist", background="red", foreground="white")

# Function to handle click events on the table
def on_click(event):
    # Get the selected item
    item_id = table.identify_row(event.y)
    column_id = table.identify_column(event.x)

    if column_id == '#6':  # DNS Lookup column
        if item_id:  # Ensure a valid row is clicked
            item_values = table.item(item_id, 'values')  # Get values from the clicked row
            url = item_values[5]  # The 6th column contains the URL
            if url.startswith("https://"):  # Check if it's a valid URL
                webbrowser.open_new_tab(url)  # Open the URL in a new tab

# Bind the click event to the function
table.bind("<Button-1>", on_click)

# Run the main loop
window.mainloop()
