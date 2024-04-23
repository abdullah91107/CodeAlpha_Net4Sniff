# Modules

import os
import time
from scapy.all import *
from colorama import Fore
from pyfiglet import Figlet
from termcolor import colored


try:

    # Variables
    separator = "." * 60
    separator_hash = "#" * 80
    pcap_folder = "Logs"
    pcap_base_filename = "Packets_Logs"
    pcap_extension = ".pcap"
    timestamp = time.strftime("%Y%m%d%H%M%S")
    pcap_filename = pcap_base_filename + "_" + timestamp + pcap_extension

    # Create the Logs folder if it doesn't exist
    if not os.path.exists(pcap_folder):
        os.makedirs(pcap_folder)

    # Construct the full path for the Pcap file
    pcap_filepath = os.path.join(pcap_folder, pcap_filename)

    # Open the Pcap File
    pcap_writer = PcapWriter(pcap_filepath, append=True, sync=True)

    # Functions

    def live_typing(text, delay=0.02):
        for char in text:
            print(char, end="", flush=True)
            time.sleep(delay)
        print("")

    def show_results_noport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size):

        print(f"{colored(packet_name, 'green')} {colored('Packet ...', 'green')}")
        print(f"")
        print(f"{colored('Source IP:         ', 'blue')}{colored(src_ip, 'yellow')}")
        print(f"{colored('Source MAC:        ', 'blue')}{colored(src_mac, 'yellow')}")
        print(f"{colored('Destination IP:    ', 'blue')}{colored(dst_ip, 'yellow')}")
        print(f"{colored('Destination MAC:   ', 'blue')}{colored(dst_mac, 'yellow')}")
        print(f"{colored('Packet Size:       ', 'blue')}{colored(size, 'yellow')}")
        print(f"")
        print(colored(separator_hash, "cyan"))
        print(f"")

    def show_results_withport(
        packet_name,
        src_ip,
        src_mac,
        dst_ip,
        dst_mac,
        size,
        src_port,
        dst_port,
    ):
        print(f"{colored(packet_name, 'green')} {colored('Packet ...', 'green')}")
        print(f"")
        print(f"{colored('Source IP:         ', 'blue')}{colored(src_ip, 'yellow')}")
        print(f"{colored('Source MAC:        ', 'blue')}{colored(src_mac, 'yellow')}")
        print(f"{colored('Destination IP:    ', 'blue')}{colored(dst_ip, 'yellow')}")
        print(f"{colored('Destination MAC:   ', 'blue')}{colored(dst_mac, 'yellow')}")
        print(f"{colored('Packet Size:       ', 'blue')}{colored(size, 'yellow')}")
        print(f"{colored('Source Port:       ', 'blue')}{colored(src_port, 'yellow')}")
        print(f"{colored('Destination Port:       ', 'blue')}{colored(dst_port, 'yellow')}")
        print(f"")
        print(colored(separator_hash, "cyan"))
        print(f"")

    def show_results_arp(
        packet_name,
        src_ip,
        src_mac,
        dst_ip,
        dst_mac,
        size,
    ):
        print(f"{colored(packet_name, 'green')} {colored('Packet ...', 'green')}")
        print(f"")
        print(f"{colored('Source IP:         ', 'blue')}{colored(src_ip, 'yellow')}")
        print(f"{colored('Source MAC:        ', 'blue')}{colored(src_mac, 'yellow')}")
        print(f"{colored('Destination IP:    ', 'blue')}{colored(dst_ip, 'yellow')}")
        print(f"{colored('Destination MAC:   ', 'blue')}{colored(dst_mac, 'yellow')}")
        print(f"{colored('Packet Size:       ', 'blue')}{colored(size, 'yellow')}")
        print(f"")
        print(colored(separator_hash, "cyan"))
        print(f"")

    try:

        def analyzer(packet):
            if packet.haslayer(IP):  # type: ignore

                src_ip = packet[IP].src  # type: ignore
                dst_ip = packet[IP].dst  # type: ignore
                src_mac = packet.src
                dst_mac = packet.dst
                if packet.haslayer(ICMP):  # type: ignore # ICMP Packet
                    packet_name = "ICMP"
                    size = len(packet[ICMP])  # type: ignore

                    show_results_noport(
                        packet_name,
                        src_ip,
                        src_mac,
                        dst_ip,
                        dst_mac,
                        size,
                    )

                if packet.haslayer(TCP):  # type: ignore # TCP Packet
                    packet_name = "TCP"
                    src_port = packet.sport
                    dst_port = packet.dport

                    size = len(packet[TCP])  # type: ignore

                    show_results_withport(
                        packet_name,
                        src_ip,
                        src_mac,
                        dst_ip,
                        dst_mac,
                        size,
                        src_port,
                        dst_port,
                    )

                if packet.haslayer(UDP):  # type: ignore # TCP Packet
                    packet_name = "UDP"
                    src_port = packet.sport
                    dst_port = packet.dport

                    size = len(packet[UDP])  # type: ignore

                    show_results_withport(
                        packet_name,
                        src_ip,
                        src_mac,
                        dst_ip,
                        dst_mac,
                        size,
                        src_port,
                        dst_port,
                    )
            elif packet.haslayer(ARP):  # type: ignore
                src_ip = packet[ARP].psrc  # type: ignore
                src_mac = packet[ARP].hwsrc  # type: ignore
                dst_ip = packet[ARP].pdst  # type: ignore
                dst_mac = packet[ARP].hwdst  # type: ignore
            pcap_writer.write(packet)

    except KeyboardInterrupt:
        print("")
        print("")
        print(
            colored(
                "Exiting ...",
                "red",
            )
        )
        print("")
        time.sleep(1)

    except:
        pass

    # Welcome Message
    welcome_msg = (
        Fore.MAGENTA + Figlet(font="slant").renderText("Net4Sniff") + Fore.RESET
    )

    time.sleep(0.5)
    print("")
    print("")
    print("")

    print(welcome_msg)
    time.sleep(1)
    print(colored("Built By: ", "blue"), end="")
    print(colored("Abdullah M. Hussein", "yellow"))
    print(colored("*NOTE: Run As Root", "red"))

    time.sleep(1)
    print("")
    live_typing("Hello There ...")
    time.sleep(1)
    live_typing("Let's Start To Sniffing All Networks Around You ...")
    time.sleep(1)

    print("")
    print(separator)
    print("")

    print("Write Your Network Interface Card Name: ")

    iface_card = input().strip().lower()
    color_ifcard = colored(iface_card, "green")
    time.sleep(1)
    print(f"You Are Sniffing From {color_ifcard}")
    time.sleep(1)
    print("Please Wait")
    time.sleep(1)
    print("")

    # Start Sniffing Function
    try:
        sniff(iface=iface_card, prn=analyzer)
    except KeyboardInterrupt:
        print("")
        print("")
        print(
            colored(
                "Exiting ...",
                "red",
            )
        )
        print("")
        time.sleep(1)


# If User Is Not Root
except PermissionError:
    print("")
    print(
        colored(
            "Permission Denied , Please Run As ROOT ! , ",
            "red",
            attrs=["bold"],
        ),
        end="",
    )
    print(
        colored(
            'Use "sudo"',
            "red",
            attrs=["bold", "underline"],
        )
    )
    print("")
    time.sleep(1)

# Exit App
except KeyboardInterrupt:
    print("")
    print("")
    print(
        colored(
            "Exiting ...",
            "red",
        )
    )
    print("")
    time.sleep(1)

# Interface Error
except OSError:
    print("")
    print(
        colored(
            "Please Choose A Correct Network Interface Card !!",
            "red",
            attrs=["bold"],
        )
    )
    print("")
    time.sleep(1)

# Any Error
except:
    print("")
    print(
        colored(
            "There Is An Error Happened, Please Run The Tool Again !",
            "red",
            attrs=["bold"],
        )
    )
    print("")
    time.sleep(1)


# Close the Pcap File
finally:
    pcap_writer.close()
