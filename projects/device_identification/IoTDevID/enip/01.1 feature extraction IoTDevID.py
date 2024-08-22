import csv

import pandas as pd
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.eap import *
from scapy.layers.inet import *
from scapy.layers.l2 import *


""" Load pcap files """
code_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
project_dir = os.path.dirname(os.path.dirname(code_dir))
data_path=os.path.join(project_dir, "data\\pcap\\enip")
def find_the_way(path,file_format):
    files_add = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            if file_format in file:
                files_add.append(os.path.join(r, file))
    return files_add
files_add=find_the_way(data_path,'.pcap')
print(f"The number of pcap files: {len(files_add)}")
for file in files_add:
    print(file)


""" Split data into train, test, validation
train=[]
test=[]
validation=[]
ite = -1;
for ii, i in enumerate(files_add):
    print(ii,i)
    if ii%5!=0:
        if (ii - ite*5 +1) % 4 == 0:
            validation.append(i)
        elif (ii - ite*5) % 4 == 0:
            test.append(i)
        else:
            train.append(i)
    else:
        train.append(i)
        ite += 1
print(len(test),len(train),len(validation)) """


""" Pcap to csv """
def folder(f_name): #this function creates a folder.
    try:
        if not os.path.exists(f_name):
            os.makedirs(f_name)
    except OSError:
        print ("The folder could not be created!")


# device information list
""" Get device information list """
def read_device_information(filepath):
    device_dict = {}

    with open(filepath, mode='r') as file:
        csv_reader = csv.reader(file)
        head_line = next(csv_reader)
        for row in csv_reader:
            key = row[0]
            device_dict[key] = row

    return device_dict
device_dict = read_device_information(os.path.join(project_dir, "data\\pcap\\device_information_anonymized.csv"))

# specify which dataset you want to create (training, validation and testing) .
# files_add=train;file_name="Aalto_train_IoTDevID.csv"
# files_add=validation;file_name="Aalto_validation_IoTDevID.csv"
# files_add=test;file_name= "../Aalto_test_IoTDevID.csv"


def shannon(data):
    LOG_BASE = 2
   # We determine the frequency of each byte
   # in the dataset and if this frequency is not null we use it for the
   # entropy calculation
    dataSize = len(data)
    ent = 0.0
    freq={} 
    for c in data:
        if c in freq:
            freq[c] += 1
        else:
            freq[c] = 1
   # to determine if each possible value of a byte is in the list
    for key in freq.keys():
        f = float(freq[key])/dataSize
        if f > 0: # to avoid an error for log(0)
            ent = ent + f * math.log(f, LOG_BASE)
    return -ent


def pre_entropy(payload):
    
    characters=[]
    for i in payload:
            characters.append(i)
    return shannon(characters)
            

def port_class(port):
    port_list=[0,53,67,68,80,123,443,1900,5353,49153]
    if port in port_list:
        return port_list.index(port)+1
    elif 0 <= port <= 1023:
        return 11
    elif  1024 <= port <= 49151 :
        return 12
    elif 49152 <=port <= 65535 :
        return 13
    else:
        return 0
    
    
def port_1023(port):
    if 0 <= port <= 1023:
        return port
    elif  1024 <= port <= 49151 :
        return 2
    elif 49152 <=port <= 65535 :
        return 3
    else:
        return 0


header="pck_size,Ether_type,LLC_dsap,LLC_ssap,LLC_ctrl,EAPOL_version,EAPOL_type,EAPOL_len,IP_version,IP_ihl,IP_tos,IP_len,IP_flags,IP_Z,IP_MF,IP_id,IP_chksum,IP_DF,IP_frag,IP_ttl,IP_proto,IP_options,IP_add_count,ICMP_type,ICMP_code,ICMP_chksum,ICMP_id,ICMP_seq,ICMP_ts_ori,ICMP_ts_rx,ICMP_ts_tx,ICMP_ptr,ICMP_reserved,ICMP_length,ICMP_nexthopmtu,ICMP_unused,TCP_seq,TCP_ack,TCP_dataofs,TCP_reserved,TCP_flags,TCP_FIN,TCP_SYN,TCP_RST,TCP_PSH,TCP_ACK,TCP_URG,TCP_ECE,TCP_CWR,TCP_window,TCP_chksum,TCP_urgptr,TCP_options,UDP_len,UDP_chksum,DHCP_options,BOOTP_op,BOOTP_htype,BOOTP_hlen,BOOTP_hops,BOOTP_xid,BOOTP_secs,BOOTP_flags,BOOTP_sname,BOOTP_file,BOOTP_options,DNS_length,DNS_id,DNS_qr,DNS_opcode,DNS_aa,DNS_tc,DNS_rd,DNS_ra,DNS_z,DNS_ad,DNS_cd,DNS_rcode,DNS_qdcount,DNS_ancount,DNS_nscount,DNS_arcount,sport_class,dport_class,sport23,dport23,sport_bare,dport_bare,TCP_sport,TCP_dport,UDP_sport,UDP_dport,payload_bytes,entropy,IP_addr,vendor,model\n"

#flags
#TCP
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
#IP
Z = 0x00
MF= 0x01
DF= 0x02


ipf=[]
tcpf=[]
degistir=""
dst_ip_list={}
Ether_adresses=[]
IP_adresses=[]
label_count=0
filename="ics_library.csv"
ths = open(filename, "w")
ths.write(header)  
device_ip_dic = set()
for numero,i in enumerate (files_add):
    #header=header
    #ths.write(header)  
    filename=str(i)
    filename=filename.replace("\\","/")
    #x = filename.rfind("/")
    filename=filename.split("/")
    
    #break
    pkt = rdpcap(i)
    #print("\n",numero,"/",len(files_add),"========"+ i[8:]+"========\n" )
    print("\n",numero+1,"/",len(files_add))
    sayaç=len(pkt)//20
    line_counter = 0
    for jj, j in enumerate (pkt):
        
        try:        
            if jj%sayaç==0:
                sys.stdout.write("\r[" + "=" * int(jj//sayaç) +  " " * int((sayaç*20 - jj)// sayaç) + "]" +  str(5*jj//sayaç) + "%")
                sys.stdout.flush()
        except:pass
        if j.haslayer(ARP):
            continue
        else:
            ts=j.time
            try:pck_size=j.len
            except:pck_size=0
            if j.haslayer(Ether):

                if j[Ether].dst not in Ether_adresses:
                    Ether_adresses.append(j[Ether].dst)
                if j[Ether].src not in Ether_adresses:
                    Ether_adresses.append(j[Ether].src)

                Ether_dst=j[Ether].dst#Ether_adresses.index(j[Ether].dst)+1
                Ether_src=j[Ether].src#Ether_adj[Ether].dstresses.index(j[Ether].src)+1

                Ether_type=j[Ether].type
            else:
                Ether_dst=0
                Ether_src=0
                Ether_type=0

            if j.haslayer(ARP):
                ARP_hwtype=j[ARP].hwtype
                ARP_ptype=j[ARP].ptype
                ARP_hwlen=j[ARP].hwlen
                ARP_plen=j[ARP].plen
                ARP_op=j[ARP].op


                ARP_hwsrc=j[ARP].hwsrc
                ARP_psrc=j[ARP].psrc
                ARP_hwdst=j[ARP].hwdst
                ARP_pdst=j[ARP].pdst

                if j[ARP].hwsrc not in Ether_adresses:
                    Ether_adresses.append(j[ARP].hwsrc)
                if j[ARP].psrc not in IP_adresses:
                    IP_adresses.append(j[ARP].psrc)           
                if j[ARP].hwdst not in Ether_adresses:
                    Ether_adresses.append(j[ARP].hwdst)
                if j[ARP].pdst not in IP_adresses:
                    IP_adresses.append(j[ARP].pdst)

                ARP_hwsrc=j[ARP].hwsrc#Ether_adresses.index(j[ARP].hwsrc)+1
                ARP_psrc=j[ARP].psrc#IP_adresses.index(j[ARP].psrc)+1
                ARP_hwdst=j[ARP].hwdst#Ether_adresses.index(j[ARP].hwdst)+1
                ARP_pdst=j[ARP].pdst#IP_adresses.index(j[ARP].pdst)+1

            else:
                ARP_hwtype=0
                ARP_ptype=0
                ARP_hwlen=0
                ARP_plen=0
                ARP_op=0
                ARP_hwsrc=0
                ARP_psrc=0
                ARP_hwdst=0
                ARP_pdst=0            

            if j.haslayer(LLC):
                LLC_dsap=j[LLC].dsap
                LLC_ssap=j[LLC].ssap
                LLC_ctrl=j[LLC].ctrl
            else:
                LLC_dsap=0
                LLC_ssap=0
                LLC_ctrl=0            

            if j.haslayer(EAPOL):
                EAPOL_version=j[EAPOL].version
                EAPOL_type=j[EAPOL].type
                EAPOL_len=j[EAPOL].len

            else:
                EAPOL_version=0
                EAPOL_type=0
                EAPOL_len=0            

            if j.haslayer(IP):

                IP_Z = 0
                IP_MF= 0
                IP_DF= 0

                IP_version=j[IP].version
                IP_ihl=j[IP].ihl
                IP_tos=j[IP].tos
                IP_len=j[IP].len
                IP_id=j[IP].id
                IP_flags=j[IP].flags

                IP_frag=j[IP].frag
                IP_ttl=j[IP].ttl
                IP_proto=j[IP].proto
                IP_chksum=j[IP].chksum

                #if j[IP].options!=0:
                IP_options=j[IP].options
                if "IPOption_Router_Alert"   in str(IP_options):
                    IP_options=1
                else:IP_options=0

                if j[Ether].src not in dst_ip_list:
                    dst_ip_list[j[Ether].src]=[]
                    dst_ip_list[j[Ether].src].append(j[IP].dst)
                elif j[IP].dst not in dst_ip_list[j[Ether].src]:
                    dst_ip_list[j[Ether].src].append(j[IP].dst)
                IP_add_count=len(dst_ip_list[j.src])

                #if IP_flags not in ipf: ipf.append(IP_flags)

                if IP_flags & Z:IP_Z = 1
                if IP_flags & MF:IP_MF = 1
                if IP_flags & DF:IP_DF = 1
                #if "Flag" in str(IP_flags):
                    #IP_flags=str(IP_flags)
                    #temp=IP_flags.find("(")
                    #IP_flags=int(IP_flags[6:temp-1])

                if j[IP].src not in IP_adresses:
                    IP_adresses.append(j[IP].src)
                if j[IP].dst  not in IP_adresses:
                    IP_adresses.append(j[IP].dst)           

                IP_src=j[IP].src#IP_adresses.index(j[IP].src)+1
                IP_dst=j[IP].dst#IP_adresses.index(j[IP].dst)+1                

            else:
                IP_Z = 0
                IP_MF= 0
                IP_DF= 0

                IP_version=0
                IP_ihl=0
                IP_tos=0
                IP_len=0
                IP_id=0
                IP_flags=0
                IP_frag=0
                IP_ttl=0
                IP_proto=0
                IP_chksum=0
                IP_src=0
                IP_dst=0
                IP_options=0
                IP_add_count=0            

            if j.haslayer(ICMP):
                ICMP_type=j[ICMP].type
                ICMP_code=j[ICMP].code
                ICMP_chksum=j[ICMP].chksum
                ICMP_id=j[ICMP].id
                ICMP_seq=j[ICMP].seq
                ICMP_ts_ori=j[ICMP].ts_ori
                ICMP_ts_rx=j[ICMP].ts_rx
                ICMP_ts_tx=j[ICMP].ts_tx
                ICMP_gw=j[ICMP].gw
                ICMP_ptr=j[ICMP].ptr
                ICMP_reserved=j[ICMP].reserved
                ICMP_length=j[ICMP].length
                ICMP_addr_mask=j[ICMP].addr_mask
                ICMP_nexthopmtu=j[ICMP].nexthopmtu
                ICMP_unused=j[ICMP].unused
            else:
                ICMP_type=0
                ICMP_code=0
                ICMP_chksum=0
                ICMP_id=0
                ICMP_seq=0
                ICMP_ts_ori=0
                ICMP_ts_rx=0
                ICMP_ts_tx=0
                ICMP_gw=0
                ICMP_ptr=0
                ICMP_reserved=0
                ICMP_length=0
                ICMP_addr_mask=0
                ICMP_nexthopmtu=0
                ICMP_unused=0

            if j.haslayer(TCP):
                TCP_FIN = 0
                TCP_SYN = 0
                TCP_RST = 0
                TCP_PSH = 0
                TCP_ACK = 0
                TCP_URG = 0
                TCP_ECE = 0
                TCP_CWR = 0
                TCP_sport=j[TCP].sport
                TCP_dport=j[TCP].dport
                TCP_seq=j[TCP].seq
                TCP_ack=j[TCP].ack
                TCP_dataofs=j[TCP].dataofs
                TCP_reserved=j[TCP].reserved
                TCP_flags=j[TCP].flags

                TCP_window=j[TCP].window
                TCP_chksum=j[TCP].chksum
                TCP_urgptr=j[TCP].urgptr
                TCP_options=j[TCP].options
                TCP_options= str(TCP_options).replace(",","-")
                if TCP_options!="0":
                    TCP_options=1
                else:
                    TCP_options=0

                #if TCP_flags not in tcpf:
                    #tcpf.append(TCP_flags)
                #print(TCP_options)
                if TCP_flags & FIN:TCP_FIN = 1
                if TCP_flags & SYN:TCP_SYN = 1
                if TCP_flags & RST:TCP_RST = 1
                if TCP_flags & PSH:TCP_PSH = 1
                if TCP_flags & ACK:TCP_ACK = 1
                if TCP_flags & URG:TCP_URG = 1
                if TCP_flags & ECE:TCP_ECE = 1
                if TCP_flags & CWR:TCP_CWR = 1   
                #print(TCP_flags)
                #if "Flag" in str(TCP_flags):
                    #TCP_flags=str(TCP_flags)
                    #temp=TCP_flags.find("(")
                    #TCP_flags=int(TCP_flags[6:temp-1])

            else:
                TCP_sport=0
                TCP_dport=0
                TCP_seq=0
                TCP_ack=0
                TCP_dataofs=0
                TCP_reserved=0
                TCP_flags=0
                TCP_window=0
                TCP_chksum=0
                TCP_urgptr=0
                TCP_options=0
                TCP_options=0
                TCP_FIN = 0
                TCP_SYN = 0
                TCP_RST = 0
                TCP_PSH = 0
                TCP_ACK = 0
                TCP_URG = 0
                TCP_ECE = 0
                TCP_CWR = 0

            if j.haslayer(UDP):
                UDP_sport=j[UDP].sport
                UDP_dport=j[UDP].dport
                UDP_len=j[UDP].len
                UDP_chksum=j[UDP].chksum
            else:
                UDP_sport=0
                UDP_dport=0
                UDP_len=0
                UDP_chksum=0

            if j.haslayer(DHCP):
                DHCP_options=str(j[DHCP].options)
                DHCP_options=DHCP_options.replace(",","-")
                if "message" in DHCP_options:
                    x = DHCP_options.find(")")
                    DHCP_options=int(DHCP_options[x-1])
                    
            else:
                DHCP_options=0            

            if j.haslayer(BOOTP):
                BOOTP_op=j[BOOTP].op
                BOOTP_htype=j[BOOTP].htype
                BOOTP_hlen=j[BOOTP].hlen
                BOOTP_hops=j[BOOTP].hops
                BOOTP_xid=j[BOOTP].xid
                BOOTP_secs=j[BOOTP].secs
                BOOTP_flags=j[BOOTP].flags
                #if "Flag" in str(BOOTP_flags):BOOTP_flags=str(BOOTP_flags)temp=BOOTP_flags.find("(") BOOTP_flags=int(BOOTP_flags[6:temp-1])
                BOOTP_ciaddr=j[BOOTP].ciaddr
                BOOTP_yiaddr=j[BOOTP].yiaddr
                BOOTP_siaddr=j[BOOTP].siaddr
                BOOTP_giaddr=j[BOOTP].giaddr
                BOOTP_chaddr=j[BOOTP].chaddr
                BOOTP_sname=str(j[BOOTP].sname)
                if BOOTP_sname!="0":
                    BOOTP_sname=1
                else:
                    BOOTP_sname=0
                BOOTP_file=str(j[BOOTP].file)
                if BOOTP_file!="0":
                    BOOTP_file=1
                else:
                    BOOTP_file=0
                
                BOOTP_options=str(j[BOOTP].options)
                BOOTP_options=BOOTP_options.replace(",","-")
                if BOOTP_options!="0":
                    BOOTP_options=1
                else:
                    BOOTP_options=0
            else:
                BOOTP_op=0
                BOOTP_htype=0
                BOOTP_hlen=0
                BOOTP_hops=0
                BOOTP_xid=0
                BOOTP_secs=0
                BOOTP_flags=0
                BOOTP_ciaddr=0
                BOOTP_yiaddr=0
                BOOTP_siaddr=0
                BOOTP_giaddr=0
                BOOTP_chaddr=0
                BOOTP_sname=0
                BOOTP_file=0
                BOOTP_options=0

            if j.haslayer(DNS):
                DNS_length=j[DNS].length
                DNS_id=j[DNS].id
                DNS_qr=j[DNS].qr
                DNS_opcode=j[DNS].opcode
                DNS_aa=j[DNS].aa
                DNS_tc=j[DNS].tc
                DNS_rd=j[DNS].rd
                DNS_ra=j[DNS].ra
                DNS_z=j[DNS].z
                DNS_ad=j[DNS].ad
                DNS_cd=j[DNS].cd
                DNS_rcode=j[DNS].rcode
                DNS_qdcount=j[DNS].qdcount
                DNS_ancount=j[DNS].ancount
                DNS_nscount=j[DNS].nscount
                DNS_arcount=j[DNS].arcount
                DNS_qd=str(j[DNS].qd).replace(",","-")
                if DNS_qd!="0":
                    DNS_qd=1
                else:
                    DNS_qd=0
                DNS_an=str(j[DNS].an).replace(",","-")
                if DNS_an!="0":
                    DNS_an=1
                else:
                    DNS_an=0
                DNS_ns=str(j[DNS].ns).replace(",","-")
                if DNS_ns!="0":
                    DNS_ns=1
                else:
                    DNS_ns=0
                DNS_ar=str(j[DNS].ar).replace(",","-")
                if DNS_ar!="0":
                    DNS_ar=1
                else:
                    DNS_ar=0
            else:
                DNS_length=0
                DNS_id=0
                DNS_qr=0
                DNS_opcode=0
                DNS_aa=0
                DNS_tc=0
                DNS_rd=0
                DNS_ra=0
                DNS_z=0
                DNS_ad=0
                DNS_cd=0
                DNS_rcode=0
                DNS_qdcount=0
                DNS_ancount=0
                DNS_nscount=0
                DNS_arcount=0
                DNS_qd=0
                DNS_an=0
                DNS_ns=0
                DNS_ar=0

            pdata=[]
            if "TCP" in j:            
                pdata = (j[TCP].payload)
            if "Raw" in j:
                pdata = (j[Raw].load)
            elif "UDP" in j:            
                pdata = (j[UDP].payload)
            elif "ICMP" in j:            
                pdata = (j[ICMP].payload)
            pdata=list(memoryview(bytes(pdata)))            
    
            if pdata!=[]:
                entropy=shannon(pdata)        
            else:
                entropy=0
            payload_bytes=len(pdata)

            sport_class=port_class(TCP_sport+UDP_sport)
            dport_class=port_class(TCP_dport+UDP_dport)
            sport23=port_1023(TCP_sport+UDP_sport)
            dport23=port_1023(TCP_dport+UDP_dport)
            sport_bare=TCP_sport+UDP_sport
            dport_bare=TCP_dport+UDP_dport#port_class(TCP_dport+UDP_dport)
            
            # label=MAC_list[j.src]
            vendor = "unknown"
            model = ""
            IP_addr = j[IP].src

            if j[IP].src in device_dict:
                IP_addr = j[IP].src
                vendor = device_dict[IP_addr][2]
                model = device_dict[IP_addr][5] + ":" + device_dict[j[IP].src][6]
            elif j[IP].dst in device_dict:
                IP_addr = j[IP].dst
                vendor = device_dict[IP_addr][2]
                model = device_dict[IP_addr][5] + ":" + device_dict[j[IP].dst][6]

            if "," in model:
                model = "\"" + model + "\""

            line=[pck_size,
            Ether_type,
            LLC_dsap,
            LLC_ssap,
            LLC_ctrl,
            EAPOL_version,
            EAPOL_type,
            EAPOL_len,
            IP_version,
            IP_ihl,
            IP_tos,
            IP_len,
            IP_flags,
            IP_Z,
            IP_MF,
            IP_id,
            IP_chksum,
            IP_DF  ,
            IP_frag,
            IP_ttl,
            IP_proto,
            IP_options,
            IP_add_count,
            ICMP_type,
            ICMP_code,
            ICMP_chksum,
            ICMP_id,
            ICMP_seq,
            ICMP_ts_ori,
            ICMP_ts_rx,
            ICMP_ts_tx,
            ICMP_ptr,
            ICMP_reserved,
            ICMP_length,
            #ICMP_addr_mask,
            ICMP_nexthopmtu,
            ICMP_unused,
            TCP_seq,
            TCP_ack,
            TCP_dataofs,
            TCP_reserved,
            TCP_flags,
            TCP_FIN,
            TCP_SYN,
            TCP_RST,
            TCP_PSH,
            TCP_ACK,
            TCP_URG,
            TCP_ECE,
            TCP_CWR   ,
            TCP_window,
            TCP_chksum,
            TCP_urgptr,
            TCP_options,
            UDP_len,
            UDP_chksum,
            DHCP_options,
            BOOTP_op,
            BOOTP_htype,
            BOOTP_hlen,
            BOOTP_hops,
            BOOTP_xid,
            BOOTP_secs,
            BOOTP_flags,
            BOOTP_sname,
            BOOTP_file,
            BOOTP_options,
            DNS_length,
            DNS_id,
            DNS_qr,
            DNS_opcode,
            DNS_aa,
            DNS_tc,
            DNS_rd,
            DNS_ra,
            DNS_z,
            DNS_ad,
            DNS_cd,
            DNS_rcode,
            DNS_qdcount,
            DNS_ancount,
            DNS_nscount,
            DNS_arcount,
            sport_class,
            dport_class,
            sport23,
            dport23,
            sport_bare,
            dport_bare,
            TCP_sport,
            TCP_dport,
            UDP_sport,
            UDP_dport, 
            payload_bytes,
            entropy,
            IP_addr,
            vendor,
            model]

            #print(line)
            line=str(line).replace("[","")
            line=str(line).replace("]","")
            #line=str(line).replace("\',","-")
            line=str(line).replace(", ",",")
            line=str(line).replace("\'","")
            line=str(line).replace("None","0")

            if vendor != "unknown":
                device_ip_dic.add(IP_addr)
                ths.write(str(line)+"\n")
                line_counter += 1

    print(f"file: {filename}, number of lines: {line_counter}")

ths.close()
print(len(device_ip_dic))

filename="Protocol.csv"
ths = open(filename, "w")
ths.write("Protocol\n")
for ii,i in enumerate(files_add):
    command="tshark -r "+i+" -T fields -e _ws.col.Protocol -E header=n -E separator=, -E quote=d -E occurrence=f > temp.csv"
    os.system(command)

    with open("temp.csv", "r") as file:
        while True:
            line=file.readline()
            if line=="":break
            if  "ARP" not in line:# this line eliminates the headers of CSV files and incomplete streams .
                ths.write(str(line))
            else:
                continue                       
      
    print("   {}  /  {}".format(ii,len(files_add)))    
    os.remove("temp.csv")
ths.close()  


df1=pd.read_csv("ics_library.csv")
#del df1["Protocol"]
df2=pd.read_csv("Protocol.csv")
df1["Protocol"]=df2["Protocol"]
file_name = "ics_library_final.csv"
df1.to_csv(file_name,index=None)


IP_flags = {'0': 1, '<Flag 0 ()>': 2, '<Flag 2 (DF)>': 3, '<Flag 1 (MF)>': 4}
TCP_flags = {'0': 1, '<Flag 2 (S)>': 2, '<Flag 18 (SA)>': 3, '<Flag 16 (A)>': 4, '<Flag 24 (PA)>': 5, '<Flag 25 (FPA)>': 6, '<Flag 17 (FA)>': 7, '<Flag 4 (R)>': 8, '<Flag 20 (RA)>': 9, '<Flag 194 (SEC)>': 10, '<Flag 1 (F)>': 11, '<Flag 152 (PAC)>': 12, '<Flag 144 (AC)>': 13,'<Flag 82 (SAE)>':14,'<Flag 49 (FAU)>':15}
BOOTP_flags = {'0': 1, '<Flag 0 ()>': 2, '<Flag 32768 (B)>': 3, 0: 1}
Protocol = {'EAPOL': 1, 'DHCP': 2, 'DNS': 3, 'TCP': 4, 'HTTP': 5, 'ICMP': 6, 'MDNS': 7, 'IGMPv3': 8, 'SSDP': 9, 'NTP': 10, 'HTTP/XML': 11, 'UDP': 12, 'SSLv2': 13, 'TLSv1': 14, 'ADwin Config': 15, 'TLSv1.2': 16, 'ICMPv6': 17, 'HTTP/JSON': 18, 'XID': 19, 'TFTP': 20, 'NXP 802.15.4 SNIFFER': 21, 'IGMPv2': 22, 'A21': 23, 'STUN': 24, 'Gearman': 25, '? KNXnet/IP': 26, 'UDPENCAP': 27, 'ESP': 28, 'SSL': 29, 'NBNS': 30, 'SIP': 31, 'BROWSER': 32, 'SABP': 33, 'ISAKMP': 34, 'CLASSIC-STUN': 35, 'Omni-Path': 36, 'XMPP/XML': 37, 'ULP': 38, 'TFP over TCP': 39, 'AX4000': 40, 'MIH': 41, 'DHCPv6': 42, 'TDLS': 43, 'RTMP': 44, 'TCPCL': 45, 'IPA': 46, 'GQUIC': 47, '0x86dd': 48, 'DB-LSP-DISC': 49, 'SSLv3': 50, 'LLMNR': 51, 'FB_ZERO': 52, 'OCSP': 53, 'IPv4': 54, 'STP': 55, 'SSH': 56, 'TLSv1.1': 57, 'KINK': 58, 'MANOLITO': 59, 'PKTC': 60, 'TELNET': 61, 'RTSP': 62, 'HCrt': 63, 'MPTCP': 64, 'S101': 65, 'IRC': 66, 'AJP13': 67, 'PMPROXY': 68, 'PNIO': 69, 'AMS': 70, 'ECATF': 71, 'LLC': 72, 'TZSP': 73,'RSIP':74,'SSHv2':75
,'DIAMETER':76
,'BFD Control':77
,'ASAP':78
,'DISTCC':79 
,'DISTCC ':79       
,'LISP':80
,'WOW':81
,'DTLSv1.0':82
,'SNMP':83
,'SMB2':84
,'SMB':85
,'NBSS':86
,'UDT':87,'HiQnet':88
,'POWERLINK/UDP':89
,'RTP':90
,'WebSocket':91
,'NAT-PMP':92
,'RTCP':93,'Syslog':94
,'Portmap':95
,'OpenVPN':96
,'BJNP':97
,'RIPv1':98
,'MAC-Telnet':99
,'ECHO':100
,'ASF':101
,'DAYTIME':102
,'SRVLOC':103
,'KRB4':104
,'CAPWAP-Control':105
,'XDMCP':106
,'Chargen':107
,'RADIUS':108
,'L2TP':109
,'DCERPC':110
,'KPASSWD':111
,'H264':112
,'FTP':113
,'FTP-DATA':114
,'ENIP':115
,'RIPv2':116
,'ICP':117,
"BACnet-APDU":118,
"IAX2":119,
"RX":120,
"HTTP2":121,
"SIP/SDP":122,
"TIME":123,
"Elasticsearch":124,
"RSL":125,
"TPCP":126,
 "IPv6":  127,
"Modbus/TCP": 128,
"ENIP": 129}

df=pd.read_csv(file_name)


df=df.replace({"IP_flags": IP_flags})
df=df.replace({"TCP_flags": TCP_flags})
df=df.replace({"BOOTP_flags": BOOTP_flags})
df=df.replace({"Protocol": Protocol})

df.to_csv(file_name,index=None)
os.remove("ics_library.csv")
os.remove("Protocol.csv")
