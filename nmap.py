from os import write
import subprocess
from subprocess import Popen, PIPE, STDOUT
import csv

# shell command execution function

def shellExe(command):
    out = subprocess.Popen(command, shell=True,
                           stdin=PIPE, stdout=subprocess.PIPE)
    # either put sudo password here or run script as root
    grep_stdout = out.communicate(input=b'PASSWORD\n')[0]
    return grep_stdout.decode()

# remote scan


# replace 172.17.1.1/24 with remote network ip address and subnet
shellExe("nmap -sn 172.17.1.1/24 > ip.txt")
active = open("scan.txt", "r")
active_ip = []

# gets list of ip address active obtained from above scan and store in active_ip list
for line in active:
    if "Nmap scan report for" in line:
        active_ip.append(line.split(" ")[4].rstrip())

# scan every ip for further enumeration
for ip in active_ip:
    shellExe("nmap -sC -sV -O -Pn "+ip+" >"+ip + ".txt")

# data extraction

# create a folder to store csv files of each IP
shellExe("mkdir -p csv_folder")

IPcsv = ["time_stamp", "IP", "mac_addr", "OS", "Device Type", "domain"]  # csv file header to store all active ips
ip_dict = []  # list to store info about every ip

for ip in active_ip:
    print("report for "+ip)
    ip_scan = open(ip+".txt", "r")
    os = ""
    macAddr = ""
    ports = []
    ports_start = False
    device_type = ""
    DNS = ""
    csvFields = ["port", "tcp/udp", "service", "version"]
    time_stamp = ""
    ip_details = {}
    ip_details["IP"] = ip

    #processing every ip and extracting data to store in csv files
    for line in ip_scan:
        if "Starting Nmap" in line:
            time_stamp = line.partition("at")[2].strip()
            ip_details["time_stamp"] = time_stamp
        
        if "DNS" in line:
            temp = line.partition("DNS")[2].strip()
            if "DNS" in temp:
                temp = temp.partition("DNS")[2].strip()
            DNS = temp
            ip_details["domain"] = DNS 
        
        if(line.startswith("PORT")):
            ports_start = True
            continue

        elif(line.startswith("MAC")):
            macAddr = line.partition(": ")[2].partition(" ")[0].rstrip()
            ip_details["mac_addr"] = macAddr
            print(macAddr)
            ports_start = False
        
        elif(ports_start):
            if(line[0].isnumeric()):
                portAndType = line.partition(" ")[0].rstrip()
                portType = portAndType.partition("/")[2].strip()
                openPort = portAndType.partition("/")[0].strip()
                service = line.partition("open")[2].lstrip(
                    " ").partition(" ")[0].rstrip()
                version = line.partition("open")[2].lstrip(
                    " ").partition(" ")[2].rstrip().lstrip()
                portDict = {'port': openPort, 'tcp/udp': portType,
                            'service': service, 'version': version}
                ports.append(portDict)
        
        elif "OS guesses" in line:
            os = line.partition(": ")[2][:11].rstrip()
            ip_details["OS"] = os
            print(os)
        elif "OS details" in line:
            os = line.partition(": ")[2][:11].rstrip()
            ip_details["OS"] = os
            print(os)
        elif "Device type:" in line:
            device_type = line.partition("Device type:")[2].strip()
            ip_details["Device Type"] = device_type
            print(device_type)

    #store information about open ports for each ip in csv files
    with open("csv_folder/"+ip+".csv", "w") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csvFields)
        writer.writeheader()
        writer.writerows(ports)
    ip_dict.append(ip_details)

#store every ip details in a single csv file
with open("ip_details.csv", "a") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=IPcsv)
    writer.writeheader()
    writer.writerows(ip_dict)
