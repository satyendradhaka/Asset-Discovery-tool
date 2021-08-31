from os import write
import subprocess
from subprocess import Popen, PIPE, STDOUT
import csv

# shell command execution function

def shellExe(command):
    out=subprocess.Popen(command, shell=True, stdin=PIPE, stdout=subprocess.PIPE)
    grep_stdout = out.communicate(input=b'kali\n')[0]
    return grep_stdout.decode()

#get arp table
shellExe("arp -a > arp.txt")

#to get every active ip in local network
#replace wlan0 with your network interface name
shellExe("arp-scan --interface=wlan0 -localnet > arp-scan.txt")


#arp output processing
file1 = open('arp.txt', 'r')
Lines = file1.readlines()
ip_connected=[]
mac_connected=[]
# Strips the newline character
for line in Lines:
    ip_connected.append(line.strip().split(' ')[1][1:-1])
    mac_connected.append(line.strip().split(' ')[3])
    print( line.strip().split(' ')[1][1:-1])
    print(line.strip().split(' ')[3])


#arp-scan output processing
file1 = open('arp-scan.txt', 'r')
Lines = file1.readlines()
ips=[]
mac=[]
mf=[]
mac_ip={}
c=0

# gets list of ip address active obtained from above scan and store in ips list

for line in Lines:
    c+=1
    if(c>2 and c<len(Lines)-2):
        print(line.strip())
        ips.append(line.strip().replace("\t"," ").split(' ')[0])
        mac.append(line.strip().replace("\t"," ").split(' ')[1])
        mf.append(line.strip().replace("\t"," ").split(' ')[2])

IPcsv=["time_stamp", "IP", "mac_addr", "OS", "Device Type", "domain"]
ip_dict=[]

for ip in ips:
    shellExe("nmap -sC -sV -O -Pn "+ip+" >"+ip+ ".txt")

for ip in ips:
    print("report for "+ip)
    ip_scan=open(ip+".txt","r")
    os=""
    macAddr=""
    ports=[]
    ports_start=False
    device_type=""
    DNS=""
    csvFields=["port","tcp/udp", "service", "version"]
    time_stamp=""
    ip_details={}
    ip_details["IP"]=ip
    for line in ip_scan:
        if "Starting Nmap" in line:
            time_stamp=line.partition("at")[2].strip()
            ip_details["time_stamp"]=time_stamp
        if "DNS" in line:
            temp=line.partition("DNS")[2].strip()
            if "DNS" in temp:
                temp=temp.partition("DNS")[2].strip()
            DNS=temp
            ip_details["domain"]=DNS
        if(line.startswith("PORT")):
            ports_start=True
            continue
        if(line.startswith("MAC")):
            macAddr=line.partition(": ")[2].partition(" ")[0].rstrip()
            ip_details["mac_addr"]=macAddr
            print(macAddr)
            ports_start=False
        if(ports_start):
            if(line[0].isnumeric()):
                portAndType=line.partition(" ")[0].rstrip()
                portType=portAndType.partition("/")[2].strip()
                openPort=portAndType.partition("/")[0].strip()
                service=line.partition("open")[2].lstrip(" ").partition(" ")[0].rstrip()
                version=line.partition("open")[2].lstrip(" ").partition(" ")[2].rstrip().lstrip()
                portDict={'port':openPort,'tcp/udp':portType,'service':service,'version':version}
                ports.append(portDict)              
        if "OS guesses" in line:
            os=line.partition(": ")[2][:11].rstrip()
            ip_details["OS"]=os
            print(os)
        if "OS details" in line:
            os=line.partition(": ")[2][:11].rstrip()
            ip_details["OS"]=os
            print(os)
        if "Device type:" in line:
            device_type=line.partition("Device type:")[2].strip()
            ip_details["Device Type"]=device_type
            print(device_type)
    with open("csv_folder/"+ip+".csv","w") as csvfile:
        writer=csv.DictWriter(csvfile, fieldnames=csvFields)
        writer.writeheader()
        writer.writerows(ports)
    ip_dict.append(ip_details)

with open("ip_details.csv","a") as csvfile:
    writer=csv.DictWriter(csvfile,fieldnames=IPcsv)
    writer.writeheader()
    writer.writerows(ip_dict)