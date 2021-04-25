from scapy.all import *
from datetime import datetime
import requests, os, re
#SID: 1800977

class ids:
    _flagsTCP = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
        }

    ip_cnt_TCP = {}               

    _THRESH=1000               
    # while True:
      #  try:
       #     requests.get('https://duckduckgo.com/').status_code
        #    break
        #except:
         #   time.sleep(5)
          #  pass
            
                
    
    def sniffPackets(self,packet):
        if packet.haslayer(IP):
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            print("IP Packet: %s  ==>  %s  , %s"%(pckt_src,pckt_dst,str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))

        if packet.haslayer(TCP):
            src_port=packet.sport
            dst_port=packet.dport
            print(", Port: %s --> %s, "%(src_port,dst_port))
            print([type(self)._flagsTCP[x] for x in packet.sprintf('%TCP.flags%')])
            self.detect_TCPflood(packet)
        else:
            print()


    def detect_TCPflood(self,packet):
        if packet.haslayer(TCP):
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            stream = pckt_src + ':' + pckt_dst

            if stream in type(self).ip_cnt_TCP:
                type(self).ip_cnt_TCP[stream] += 1
            else:
                type(self).ip_cnt_TCP[stream] = 1

            for stream in type(self).ip_cnt_TCP:
                pckts_sent = type(self).ip_cnt_TCP[stream]
                if pckts_sent > type(self)._THRESH:
                    src = stream.split(':')[0]
                    dst = stream.split(':')[1]
                    print("Excessive packets from: %s --> %s, This has been logged in /var/log/ids_log." %(src,dst))


def main():
    user_input = input("please ensure this is run with root privilege!")
    os.system('apt install net-tools -y')
    os.system('ifconfig | grep "flags"')
    adapter = input("which adapter are you using? (example: wlan0) : ")
    sniff(filter="ip",iface=adapter,prn=ids().sniffPackets)
