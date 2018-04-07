# -*- coding: UTF-8 -*-
import dpkt
import socket
import datetime
import matplotlib.pyplot as plt

first = 0
first_ts = 0
first_seq = 0
first2 = 0
first_ts2 = 0
first_seq2 = 0

def printPcap(pcap):
    global first
    global first_ts
    global first_seq
    global first2
    global first_ts2
    global first_seq2
    
    list_ts = []
    list_sqn = []
    seq = 0
    last_ts = 0
    list_ts2 = []
    list_sqn2 = []
    seq2 = 0
    last_ts2 = 0
    

    for (ts,buf) in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            print 'Non IP Packet type not supported %s' % eth.data.__class__.__name__
            continue

        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)

        tcp = ip.data
        if src == "140.113.195.91" and tcp.dport == 55488:
            if first == 0:
                first = 1
                first_ts = ts
		last_ts = ts
                first_seq = tcp.seq
	    if ts-last_ts <= 0.1 :
		seq = seq + len(buf)
	    else :
		list_sqn.append(seq*10)
		list_ts.append(ts-first_ts)
		last_ts = ts
		seq = 0
	if src == "140.113.195.91" and tcp.dport == 55486:
            if first2 == 0:
                first2 = 1
                first_ts2 = ts
		last_ts2 = ts
                first_seq2 = tcp.seq
	    if ts-last_ts2 <= 0.1 :
		seq2 = seq2 + len(buf)
	    else :
		list_sqn2.append(seq2*10)
		list_ts2.append(ts-first_ts2)
		last_ts2 = ts;
		seq2 = 0
            
           
    draw_sqn(list_ts,list_sqn,list_ts2,list_sqn2)

def draw_sqn(list_ts,list_sqn,list_ts2,list_sqn2):
    plt.plot(list_ts,list_sqn)
    plt.plot(list_ts2,list_sqn2)
    plt.xlabel("Time");
    plt.ylabel("Sequence Number");
    plt.title("time/sequence graph")
    plt.show()

def main():
    f = open('lab1_0516310_rx_wget.pcap')
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)

if __name__ == '__main__':
    main()

