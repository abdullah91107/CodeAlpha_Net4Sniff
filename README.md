
# Description

Net4Sniff is a Python-based network sniffer that captures and analyzes network traffic.
It effectively sniffs and displays information about UDP, TCP, ARP, and ICMP packets, providing details such as:

- Destination and Source IP Addresses
- Destination and Source MAC Addresses
- Destination and Source Port Numbers (for TCP and UDP packets)
- Packet Size


# Features

- Cross-platform compatibility (works on Windows, macOS, and Linux)
- User-friendly Command Line Interface (CLI) with clear packet information
- Store all sniffed packets in ```'pcap'``` file
- Just need your Network Interface Card (NIC) Name and Let's SNIFF
- Customizable filtering options (potential future implementation)

# Installation
Now Let's Install This Tool.

## Prerequisites:
### Install Python:


First, you need to install Python on your device

For Kali, you need to update first 
```
sudo apt update
```
Then, Download Python
```
sudo apt install python3
```

Ok, To verify that to have Python, Check Version 
```
python3 --version
```

Now You Have Python

### Install Libraries:
You need to install some libraries before using the tool like:

- ```os```: Provides operating system interaction capabilities.
- ```time```: Enables functionalities related to time management.
- ```scapy```: The core network sniffing library used for packet capture and analysis.
- ```colorama```: Enhances terminal output with color formatting.
- ```pyfiglet```: Creates a visually appealing ASCII art banner for the tool.
- ```termcolor```: Provides additional color formatting options for the terminal output.

[ time & os ] is already installed on your device

To Install Other Libraries:
```
pip3 install scapy colorama pyfiglet termcolor -y
```


## Install Net4Sniff

Go to your installation folder, open your terminal, and write this:
```
git clone https://github.com/abdullah91107/CodeAlpha_Net4Sniff.git
```

# How To Use
Congratulations You Got Net4Sniff Tool
You Can Now Start To Sniff All Networks Around You
Start using it by writing in terminal
```
sudo python3 Net4Sniff.py           
```
NOTE: YOU MUST BE ROOT WHEN YOU USE IT 

Once you run the tool , It asks you to write your Network Interface Card (NIC) name, You must write it correctly like ```wlan0```, ```eth0```, etc

After that, You can see packets in your network and some information about it 

# Logs
All packets you sniff will be logged in a file with an extension ```.pcap``` 
The file will be in the ```Logs```


# Author
This project is made for CodeAlpha by Abdullah M. Hussein

I hope this comprehensive README.md file proves helpful!










