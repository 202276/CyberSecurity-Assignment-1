# CyberSecurity-Assignment-1

File 1:
mycode.py
- This is used to create IP packet.
- Before executing the file, permissions need to be changed so that the file is executable.

File 2:
sniffPkt.py
- First run the ifconfig command to get the list of interfaces and from there get the interface ID you want to sniff on.
- Now add this interface ID to your script from where you want to sniff packets.
- Run the file sniffPkt.py in Terminal 1 as root user since this needs root privilege to sniff packets. The program will now start sniffing till it gets a packet.
- Ping google.com from Terminal 2.
- Terminal 1 where the program was executed now prints information of packet it received. 

File 3:
sniffICMPPkt.py
- Filter parameter in the above program helps in filtering only those packets that are needed by the sniffer
- First run the ifconfig command to get the list of interfaces and from there get the interface ID you want to sniff on.
- Now add this interface ID to your script from where you want to sniff packets.
- Add filter parameter to your program. In our example, since we want to sniff on any ICMP packets, filter = ‘icmp’ Is provided
- Run the file sniffICMPPkt.py in Terminal 1 as root user since this needs root privilege to sniff packets. The program will now start sniffing till it gets a packet
- Ping gmail.com from Terminal 2.
- Terminal 1 where the program was executed now prints information of ICMP packet it received. 
- One can first see an echo-request sent from src=10.0.2.5 (local) to dst= 142.250.183.165 (gmail) and then an echo-reply is got from src=142.250.183.165 (gmail) to dst=10.0.2.5 (local).

File 4:
captureTCPPkt.py
- TELNET server is running on port number 23.
- Run the script captureTCPPkt.py as the seed attacker.
- Now attacker starts sniffing on the interfaces mentioned and for tcp packets from the host VM whose IP is 10.9.0.1
- Local host pings telnet 10.9.0.6 and attacker will be able to get the TCP packets captured.

File 5:
subnet.py 
- Explained in File 6 point

File 6:
createPacketSubnet.py
- Run the script subnet.py as sudo user in Terminal 1
- Run the script to create packets createPacketSubnet.py in Terminal 2 as sudo user
- In the example here, 2 packets are created
- The captured packet details are displayed by the program subnet.py
- Program is used to capture network packets from specific network interfaces that are destined to a specific network. It then displays relevant information of the packet.
- pkt_capture(pkt) is a function defined that takes a network packet as input and displays its information using show() method.
- Network interfaces ('enp0s3', 'lo') are from where packets are being sniffed.
- Capture filter f is set to 'dst net 128.230.0.0/16', the program capture packets only from whose destination specified in the program

File 7:
spoofICMPPkt.py
- In this example, attacker node runs the script spoofICMPPkt.py where ICMP echo request packet is spoofed and sent to Host B (10.9.0.6) on the same network.

File 8:
traceroute.py
- The script sends Internet Control Message Protocol (ICMP) echo requests (similar to a 'ping') to a destination IP Address ('142.250.199.174' in this case) with incrementing Time-To-Live (TTL) values.
- Each router along the path decreases the TTL value by 1 before forwarding the packet. When the TTL value reaches zero, the router sends an ICMP "time exceeded" message back to the source, thereby revealing its IP address.
- This script starts with a TTL of 1 and increases it for each iteration, thus discovering and printing each router ("hop") along the path to the final destination until it receives an ICMP echo reply from the target.
- If no intermediary router responds within a 2 second timeout, the script assumes a 'hop' occurred.

File 9:
sniffingAndThenSpoofingA.py
- Run the program sniffingAndThenSpoofingA.py as attacker on seed
- This will not start sniffing the interfaces given in filters
- Start Host A and ping 1.2.3.4 (a non-existing host on the Internet).
- If the program were not there then there is 100% packet loss because it will never return to the source

File 10:
sniffingAndThenSpoofingB.py
- Run the program sniffingAndThenSpoofingB.py as attacker on seed
- This will now start sniffing the interfaces given in filters
- Start Host A (10.9.0.5) and ping 10.9.0.99 (a non-existing host on the LAN)."Destination Host Unreachable", it indicates that the packet was successfully sent out from local machine, but a router along the path towards the destination (10.9.0.99 in this case) could not find a route to that host. 
- This can happen due to a few reasons, including but not limited to:
o	IP address trying to be reached does not exist on the network.
o	Network with IP address trying to be reached due to network issues or the network doesn't exist.
o	Firewall or security rules preventing the host from sending/receiving packets.
o	To add, if one of trying to spoof ICMP packets (specifically ICMP echo replies) to make a host seem reachable when it's not, strategy's success depends on the network topology and how the routers in the network handle "Destination Unreachable" messages
o	In some networks, a "Destination Unreachable" message from a router can override and nullify any ICMP echo replies one is trying to spoof, because the router's message is telling the original sender that the host isn't reachable.
- Now ping 8.8.8.8 (an existing host on the Internet). Since this exists on the internet, duplicate responses are received. This is because real destination of google is responding to the source, added to which the program sniffingAndThenSpoofingA.py is also responding to the source.

File 11:
pktSniffingPrg.py
- Execute the program as root user
- Ping 8.8.8.8 from Host A
- Host and destination IP are printed since the program is sniffing

File 12:
promiscFalse.py
- Run this file as a sudo user

File 13:
captureICMPPkt2hosts.py
- An attacker runs the file with root privilege
- Host B pings Host A and attacker is sniffing on the interfaces as defined in filter expression
- The program prints a summary line for every ICMP packet it sniffs that is either from Host A (10.9.0.5) to Host B (10.9.0.6) or from Host B (10.9.0.6) to Host A (10.9.0.5) on the specified network interfaces.

File 14:
captureTCPPktdestn10To100.py
- In the example being demonstrated, attacker runs the script with root privileges.
- Telnet is used to capture TCP packet and is sent from Host A to Host B

File 15:
pwdSniff.py
- Run the script as attacker with root privilege
- Start Host A and ping Host B ->telnet 10.9.0.6
- Notice that the password entered can be seen by the attacker

File 16:
spoofPgr.py
- In the program we have considered, a UDP packet is created with random source and destination as one of our host machines
- The packet is then sent by a user having root privilege
- Packet details show information on source and destination address 

File 17:
spoofICMPEchoRequest.py
- In this example, we create a spoof ICMP request from attacker machine with source IP as victim (10.0.2.5) and sent to remote server (1.2.3.4)
- Remote server responded to ICMP request and sent it to the victim (10.0.2.6)
- We are trying to spoof an ICMP Echo request from 1.2.3.4 

File 18:
sniffAndThenSpook2dot3.py
- Host A pings 1.2.3.4 
- Attacker machine is in promiscuous mode. Execute the spoofing program
- NIC captures all packets that reached and the program then processed in such a way, it modified the destination as source and source as destination.
- Once packet is created it sends the packet out and host A receives it. 
- Regardless of whether machine X is alive or not, (in our case 1.2.3.4), the ping program will always receive a reply, indicating that X is alive

Detailed steps and screenhot of executions/wireshark reference is added to the detailed report.

