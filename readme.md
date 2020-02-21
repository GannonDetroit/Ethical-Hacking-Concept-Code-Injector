#Ethical-Hacking-Concept-Code-Injector
 - While there are several code injecting tools available on the net, I wanted to create a low-level one that will work for linux machines and is written using python, netfilterqueue, and scapy.

 - This tool is just a proof of concept and not intended to be used for any illegal or unethical activity. It should only be used on machines and networks that you as a user own and/or have written permission to use and access.

# Notes
 - Pay attention to notes commented in the code

 - run with python2, not 3.

 - before running code, you'll need to run these commands:
`iptables --flush`
`iptables -I FORWARD -j NFQUEUE --queue-num 0` [replace with INPUT and then OUTPUT for demos]

# Debugging
 1) You need to make sure that there is no rule in the iptables first:

 iptables -- flush

 2) re-run:

 iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

 3)knowing that the packets reached your local PC and if you are a MITM you need to 
 trap the packets in the INPUT and OUTPUT in a queue and treat them from this queue. 
 So you need to run:
 iptables -I OUTPUT -j NFQUEUE --queue-num 0

 iptables -I INPUT -j NFQUEUE --queue-num 0