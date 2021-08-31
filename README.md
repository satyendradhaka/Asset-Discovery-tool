# Asset-Discovery-tool
Flipkart Grid 3.0 Information Security Challange

## Setting up enviroment for remote network scanning:

Follow [this](https://isc.sans.edu/forums/diary/Tunneling+scanners+or+really+anything+over+SSH/24286/) article for creating ssh tunnel to remote network so that we can do arp scans and send and recieve icmp pings also.

```
https://isc.sans.edu/forums/diary/Tunneling+scanners+or+really+anything+over+SSH/24286/
```

After this tunnels been setup run the below command to scan your remote network.

```bash
python nmap.py
```

for local system scanning you dont need to setup anything, just run the below command:
```bash
sudo python arp-scan.py
```
It will create a csv files of all active ip's and create individual scan files for each ip.
