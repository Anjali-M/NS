#Scapy to read and analyze the .pcap data
from scapy.all import *
import time
#socket is used for DNS Querying
import socket
#to plot the data
from matplotlib import pyplot as plt

#This method returns the domain name of the Dest IP Addr
def lookup(addr):
        try:
             return socket.gethostbyaddr(addr)
        except socket.herror:
             return "None", "None", "None"

def main(filename):

    #DNS list  
    iplugDNSlist = ['mqtt.evrythng.com','api.evrythng.com']
    lifxDNSlist= ['pool.ntp.org', 'v2.broker.lifx.co']
    dropcamDNSlist= ['oculus1170-vir.dropcam.com','pool.ntp.org', 'nexus.dropcam.com','files.dropcam.com']
    echoDNSlist = ['softwareupdates.amazon.com','www.example.org','pindorama.amazon.com','www.example.com','www.meethue.com','www.example.net','device-metrics-us.amazon.com']

    #MAC Adrresses of 
    MACAddr_dropcam= '30:8c:fb:2f:e4:b2'
    MACAddr_lifx="d0:73:d5:01:83:08"
    MACAddr_iplug="74:c6:3b:29:d7:1d"
    MACAddr_echo="44:65:0d:56:cc:d3"
   
    #The output of the Reverse DNS Lookup is written to domainNamesOutput.txt
    Addr_File = open("AddressOutput.txt", "a")
    lifx_File = PcapWriter("lifx.pcap", append=True, sync=True)
    dropCam_File = PcapWriter("dropCam.pcap", append=True, sync=True)
    iplug_File = PcapWriter("iplug.pcap", append=True, sync=True)
    echo_File = PcapWriter("echo.pcap", append=True, sync=True)

    #Reading the .pcap file and extracting the required attributes.
    pkts = rdpcap(filename)
    

    i=0

    for p in pkts:
        
        print("Analyzing Packet : ",i)
        i=i+1
        
        if Ether in p and IP in p:
            MAC_src = p[Ether].src
            MAC_dst = p[Ether].dst
            ip_src = p[IP].src
            ip_dst = p[IP].dst
            time = p.time
            size = p.wirelen
        
            name_src,alias_src,addresslist_src = lookup(str(ip_src))
            name_dst,alias_dst,addresslist_dst = lookup(str(ip_dst))

            Addr_File.write("src IP : "+ip_src+" "+"\tDst IP : "+ip_dst+"\tDomain Name (src) : "+name_src+"\tDomain Name (dst) : "+name_dst+"\n""Destination MAC Addr : "+MAC_dst+"\tSource MAC Addr : "+MAC_src+"\n")


            Addr_File.write("\n_________________________________________________________________________________________________________________________\n")

            if ((name_src in iplugDNSlist) or (name_dst == iplugDNSlist)) or ((MAC_src == MACAddr_iplug) or (MAC_dst == MACAddr_iplug)) :
                iplug_File.write(p)
            elif ((name_src == lifxDNSlist) or (name_dst == lifxDNSlist)) or ((MAC_src == MACAddr_lifx) or (MAC_dst == MACAddr_lifx)):
                lifx_File.write(p)
            elif ((name_src == dropcamDNSlist) or (name_dst == dropcamDNSlist)) or ((MAC_src == MACAddr_dropcam) or (MAC_dst == MACAddr_dropcam)):
                dropCam_File.write(p)
            elif ((name_src in echoDNSlist) or (name_dst in echoDNSlist)) or ((name_src in MACAddr_echo) or (name_dst in MACAddr_echo)):
                echo_File.write(p)

if __name__ == "__main__":
    filename = '/home/swati/BITS/NS/Project/demoData1k.pcap'
    main(filename)
