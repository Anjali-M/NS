#Scapy to read and analyze the .pcap data
from scapy.all import *
import time
#socket is used for DNS Querying
import socket
#to plot the data
from matplotlib import pyplot as plt

def main(filename,device):

    #dictionary to store the timestamp and byte size values for plotting the graph.
    traffic_dict={ }
  
    #Reading the .pcap file and extracting the required attributes.
    pkts = rdpcap(filename)

    for p in pkts:
           
            pktTime = str(p.time)
            size = len(p)
            
            if pktTime not in traffic_dict:
                traffic_dict[pktTime] = int(size)
            else:
                size=int(size)+traffic_dict.get(pktTime)
                traffic_dict[pktTime] = int(size)
                
           
    #sorting the time values before plotting    
    plist = sorted(list(traffic_dict.items()))
   
    #Plotting the graph for first 100 time values
    plot_list=plist[:100]

    print("starting to plot.....")

    x, y = zip(*plot_list) 
    plt.plot(x,y)
    plt.title(device)
    plt.xlabel("Timestamp")
    plt.ylabel("Bytes/sec")
    plt.show()

    print("Graph plotted.....")

if __name__ == "__main__":

    filename = './EchoPkts.pcap'
    device = "Amazon Echo"
    main(filename,device)

    filename = './ihomeplugPkts.pcap'
    device = "IHOME PLUG"
    main(filename,device)

    filename = './LifxPkts.pcap'
    device = "Lifx"
    main(filename,device)

    filename = './dropCamPkts.pcap'
    device = "DropCam"
    main(filename,device)
    

