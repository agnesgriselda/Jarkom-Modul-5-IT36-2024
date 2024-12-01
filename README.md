# Jarkom-Modul-5-IT36-2024

## Laporan Resmi Modul 5 : Firewall

### IT36

| Nama                        | NRP           |
|-----------------------------|---------------|
| Fico Simhanandi                | 5027231030   |
| Agnes Zenobia Griselda Petrina | 5027231034    |



## Topologi

![image](https://github.com/user-attachments/assets/0c5c5764-89eb-4870-b0e8-e30c975d8084)

## Tree

![image](https://github.com/user-attachments/assets/eb6b015b-e14d-41d1-85c7-909872ab88c7)

## Setup

## Routers

### NewEridu
```
auto eth0
iface eth0 inet dhcp

#A6
auto eth1
iface eth1 inet static
    address 10.81.1.225
    netmask 255.255.255.252
#A5
auto eth2
iface eth2 inet static
    address 10.81.1.221
    netmask 255.255.255.252

up echo nameserver 192.168.122.1 > /etc/resolv.conf

#A1
up route add -net 10.81.1.216 netmask 255.255.255.252 gw 10.81.1.222

#A2
up route add -net 10.81.1.128 netmask 255.255.255.192 gw 10.81.1.222

#A3
up route add -net 10.81.1.192 netmask 255.255.255.248 gw 10.81.1.222

#A4
up route add -net 10.81.1.200 netmask 255.255.255.248 gw 10.81.1.222

#A7
up route add -net 10.81.0.0 netmask 255.255.255.0 gw 10.81.1.226

#A8
up route add -net 10.81.1.208 netmask 255.255.255.248 gw 10.81.1.226

#A9
up route add -net 10.81.1.0 netmask 255.255.255.128 gw 10.81.1.226
```

### Bashrc
```sh
IP_ETH0=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source $IP_ETH0
```

#### SixStreet (DHCP Relay)
```
#A5
auto eth0
iface eth0 inet static
    address 10.81.1.222
    netmask 255.255.255.252
#A4
auto eth1
iface eth1 inet static
    address 10.81.1.202
    netmask 255.255.255.248
#A3
auto eth2
iface eth2 inet static
    address 10.81.1.194
    netmask 255.255.255.248

up echo nameserver 192.168.122.1 > /etc/resolv.conf

#Default
up route add -net 0.0.0.0 netmask 0.0.0.0 gw 10.81.1.221

#A1
up route add -net 10.81.1.216 netmask 255.255.255.252 gw 10.81.1.195

#A2
up route add -net 10.81.1.128 netmask 255.255.255.192 gw 10.81.1.196
```

### Bashrc
```sh
apt-get update
apt install isc-dhcp-relay -y

echo 'SERVERS="10.81.1.204"
INTERFACES="eth0 eth1 eth2 eth3"
OPTIONS=""
' > /etc/default/isc-dhcp-relay

echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

service isc-dhcp-relay restart
```

### ScootOutpost
```
#A3
auto eth0
iface eth0 inet static
    address 10.81.1.195
    netmask 255.255.255.248
#A1
auto eth1
iface eth1 inet static
    address 10.81.1.217
    netmask 255.255.255.252

up echo nameserver 192.168.122.1 > /etc/resolv.conf

#Default
up route add -net 0.0.0.0 netmask 0.0.0.0 gw 10.81.1.194
```

### OuterRing (DHCP Relay)
```
#A3
auto eth0
iface eth0 inet static
    address 10.81.1.196
    netmask 255.255.255.248
#A2
auto eth1
iface eth1 inet static
    address 10.81.1.129
    netmask 255.255.255.192

up echo nameserver 192.168.122.1 > /etc/resolv.conf

#Default
up route add -net 0.0.0.0 netmask 0.0.0.0 gw 10.81.1.194
```

### Bashrc
```sh
apt-get update
apt install isc-dhcp-relay -y

echo 'SERVERS="10.81.1.204"
INTERFACES="eth0 eth1 eth2 eth3"
OPTIONS=""
' > /etc/default/isc-dhcp-relay

echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

service isc-dhcp-relay restart
```

### LuminaSquare (DHCP Relay)
```
#A6
auto eth0
iface eth0 inet static
    address 10.81.1.226
    netmask 255.255.255.252
#A8
auto eth1
iface eth1 inet static
    address 10.81.1.209
    netmask 255.255.255.248
#A7
auto eth2
iface eth2 inet static
    address 10.81.0.1
    netmask 255.255.255.0

up echo nameserver 192.168.122.1 > /etc/resolv.conf

#Default
up route add -net 0.0.0.0 netmask 0.0.0.0 gw 10.81.1.225

#A9
up route add -net 10.81.1.0 netmask 255.255.255.128 gw 10.81.1.210
```

### Bashrc
```sh
apt-get update
apt install isc-dhcp-relay -y

echo 'SERVERS="10.81.1.204"
INTERFACES="eth0 eth1 eth2 eth3"
OPTIONS=""
' > /etc/default/isc-dhcp-relay

echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

service isc-dhcp-relay restart
```

### BalletTwins (DHCP Relay)
```
#A8
auto eth0
iface eth0 inet static
    address 10.81.1.210
    netmask 255.255.255.248
#A9
auto eth1
iface eth1 inet static
    address 10.81.1.1
    netmask 255.255.255.128

up echo nameserver 192.168.122.1 > /etc/resolv.conf

#Default
up route add -net 0.0.0.0 netmask 0.0.0.0 gw 10.81.1.209
```

### Bashrc
```sh
apt-get update
apt install isc-dhcp-relay -y

echo 'SERVERS="10.81.1.204"
INTERFACES="eth0 eth1 eth2 eth3"
OPTIONS=""
' > /etc/default/isc-dhcp-relay

echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

service isc-dhcp-relay restart
```

## DNS Server

### HDD
```
#A4
auto eth0
iface eth0 inet static
	address 10.81.1.203
	netmask 255.255.255.248
	gateway 10.81.1.202

up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

### Bashrc
```sh
echo 'nameserver 192.168.122.1' > /etc/resolv.conf
apt-get update
apt-get install bind9 netcat -y

echo 'options {
        directory "/var/cache/bind";

        forwarders {
                192.168.122.1;
        };

        // dnssec-validation auto;
        allow-query{any;};
        auth-nxdomain no;
        listen-on-v6 { any; };
}; ' > /etc/bind/named.conf.options

service bind9 restart
```

## DHCP Server

### Fairy
```
#A4
auto eth0
iface eth0 inet static
	address 10.81.1.204
	netmask 255.255.255.248
	gateway 10.81.1.202

up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

### Bashrc
```sh
# Opsi dasar DHCP
apt-get update
apt-get install isc-dhcp-server netcat -y

echo 'INTERFACESv4="eth0"' > /etc/default/isc-dhcp-server

# Subnet A7 (LuminaSquare untuk Jane dan Policeboo)
echo 'subnet 10.81.0.0 netmask 255.255.255.0 {
    range 10.81.0.2 10.81.0.254;
    option routers 10.81.0.1;
    option broadcast-address 10.81.0.255;
    option domain-name-servers 10.81.1.203; # HDD sebagai DNS Server
    default-lease-time 600;
    max-lease-time 7200;
}

# Subnet A9 (BalletTwins untuk Lycaon dan Ellen)
subnet 10.81.1.0 netmask 255.255.255.128 {
    range 10.81.1.2 10.81.1.126;
    option routers 10.81.1.1;
    option broadcast-address 10.81.1.127;
    option domain-name-servers 10.81.1.203;
    default-lease-time 600;
    max-lease-time 7200;
}

# Subnet A2 (OuterRing untuk Caesar dan Burnice)
subnet 10.81.1.128 netmask 255.255.255.192 {
    range 10.81.1.130 10.81.1.190;
    option routers 10.81.1.129;
    option broadcast-address 10.81.1.191;
    option domain-name-servers 10.81.1.203;
    default-lease-time 600;
    max-lease-time 7200;
}
subnet 10.81.1.192 netmask 255.255.255.248 {} # A3
subnet 10.81.1.200 netmask 255.255.255.248 {} # A4
subnet 10.81.1.208 netmask 255.255.255.248 {} # A8
subnet 10.81.1.220 netmask 255.255.255.252 {} # A5
subnet 10.81.1.224 netmask 255.255.255.252 {} # A6
' > /etc/dhcp/dhcpd.conf

service isc-dhcp-server restart
```

## Webservers

### HIA
```
#A8
auto eth0
iface eth0 inet static
	address 10.81.1.211
	netmask 255.255.255.248
	gateway 10.81.1.209

up echo nameserver 192.168.122.1 > /etc/resolv.conf

```

### Bashrc
```sh
apt-get update
apt-get install apache2 netcat -y
apt-get install php libapache2-mod-php -y
service apache2 start

echo '<?php echo "Welcome to " . gethostname(); ?>' > /var/www/html/index.php


service apache2 restart
```

### HollowZero
```
#A1
auto eth0
iface eth0 inet static
	address 10.81.1.218
	netmask 255.255.255.252
	gateway 10.81.1.217

up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

### Bashrc
```sh
apt-get update
apt-get install apache2 netcat -y
apt-get install php libapache2-mod-php -y
service apache2 start

echo '<?php echo "Welcome to " . gethostname(); ?>' > /var/www/html/index.php

service apache2 restart
```

## Client

### Lycaon <3
```
#A9
auto eth0
iface eth0 inet dhcp
up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

### Ellen
```
#A9
auto eth0
iface eth0 inet dhcp

up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

### Burnice
```
#A2
auto eth0
iface eth0 inet dhcp

up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

### Caesar
```
#A2
auto eth0
iface eth0 inet dhcp

up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

### PoliceBoo
```
#A7
auto eth0
iface eth0 inet dhcp

up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

### Jane
```
#A7
auto eth0
iface eth0 inet dhcp

up echo nameserver 192.168.122.1 > /etc/resolv.conf
```

# Note!
Incase something goes wrong with dhcp server
### .sh in fairy
```sh
service isc-dhcp-server stop
rm -f /var/run/dhcpd.pid
service isc-dhcp-server start
```

# Soal 2
## Fairy sh Conf to block ip
```sh
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
```	
## Fairy sh Conf to remove block
```sh
iptables -D INPUT -p icmp --icmp-type echo-request -j DROP
iptables -D OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
```

![Ping_to_Fairy](https://github.com/user-attachments/assets/57438403-6f90-44d1-bbd0-5c922a5d88db)

![Fairy_Ping](https://github.com/user-attachments/assets/a444a517-0b04-43a2-a230-22f0c237e83a)

# Soal 3
## HDD conf to only accept access from Fairy
```sh
iptables -A INPUT -s 10.81.1.204 -j ACCEPT
iptables -A INPUT -j REJECT
```

## Testing
```sh
#HDD
nc -l -p 1234

#Fairy
nc 10.81.1.203 1234
```

![Message_seen_from_hdd](https://github.com/user-attachments/assets/4d57cf28-4f82-42c3-885c-e377a724585c)

![message_from_lycaon](https://github.com/user-attachments/assets/a816c234-3230-411b-ba96-35b39e15567f)

![Message_from_fairy](https://github.com/user-attachments/assets/034f46f8-2e26-4a80-934e-16972c0dc61d)

# Soal 4
## iptables configurations (HollowZero)
```sh
iptables -A INPUT -p tcp -s <IP_Burnice> --dport 80 -m time --timestart 00:00 --timestop 23:59 --weekdays Mon,Tue,Wed,Thu,Fri -j ACCEPT

iptables -A INPUT -p tcp -s <IP_Caesar> --dport 80 -m time --timestart 00:00 --timestop 23:59 --weekdays Mon,Tue,Wed,Thu,Fri -j ACCEPT

iptables -A INPUT -p tcp -s <IP_Jane> --dport 80 -m time --timestart 00:00 --timestop 23:59 --weekdays Mon,Tue,Wed,Thu,Fri -j ACCEPT

iptables -A INPUT -p tcp -s <IP_Policeboo> --dport 80 -m time --timestart 00:00 --timestop 23:59 --weekdays Mon,Tue,Wed,Thu,Fri -j ACCEPT

iptables -A INPUT -p tcp --dport 80 -j REJECT
```

## Accessing
```sh
curl http://10.81.1.218
```

![Policeboo](https://github.com/user-attachments/assets/730223f1-a070-4289-97d1-2b19d988d958)

![Jane](https://github.com/user-attachments/assets/3cfa362b-f2ef-4239-9fe5-d957adae92af)

![Caesar](https://github.com/user-attachments/assets/fdf0c17b-c514-4d96-aa80-c88de98cc6f7)

![Burnice](https://github.com/user-attachments/assets/d8421ca7-394b-4e51-9497-9ad8ccd68df2)

![Accesed_Sunday](https://github.com/user-attachments/assets/aa441e2a-eedf-4112-bd93-94d665ee35d4)

# Soal 5
## iptable configurations (HIA)
```sh
iptables -A INPUT -p tcp -s <IP Ellen> --dport 80 -m time --timestart 01:00 --timestop 14:00 --weekdays Mon,Tue,Wed,Thu,Fri,Sat,Sun -j ACCEPT

iptables -A INPUT -p tcp -s <IP Lycaon> --dport 80 -m time --timestart 01:00 --timestop 14:00 --weekdays Mon,Tue,Wed,Thu,Fri,Sat,Sun -j ACCEPT

iptables -A INPUT -p tcp -s <IP Jane> --dport 80 -m time --timestart 20:00 --timestop 16:00 --weekdays Mon,Tue,Wed,Thu,Fri,Sat,Sun -j ACCEPT

iptables -A INPUT -p tcp -s <IP Policeboo> --dport 80 -m time --timestart 20:00 --timestop 16:00 --weekdays Mon,Tue,Wed,Thu,Fri,Sat,Sun -j ACCEPT

iptables -A INPUT -p tcp --dport 80 -j REJECT
```
### Note! karena waktu menggunakan UTC/GMT+0 jadi waktu diubah sedikit agar sesuai karena WIB = GMT+7

## Accessing
```sh
curl http://10.81.1.211
```

![Policebooo](https://github.com/user-attachments/assets/031bf42e-b1ca-4d67-aa01-b5728f6c6c81)

![Lycaonnnnn](https://github.com/user-attachments/assets/bee1317e-6d1d-4295-a1bc-2670069c39aa)

![Jane](https://github.com/user-attachments/assets/f56b2f10-5a68-4b5c-b981-cd0d77cd2296)

![ellen](https://github.com/user-attachments/assets/ef58232b-ac6d-4991-810a-211817dd7e43)

# Soal 6
## iptable configurations (HIA)
```sh
# Create a custom chain to detect port scans
iptables -N PORTSCAN

# Rate limit for port scanning (maximum 25 connections per 10 seconds on ports 1-100)
iptables -A INPUT -p tcp --dport 1:100 -m state --state NEW -m recent --set --name portscan
iptables -A INPUT -p tcp --dport 1:100 -m state --state NEW -m recent --update --seconds 10 --hitcount 25 --name portscan -j PORTSCAN

# Log the scanning attempts (optional)
iptables -A PORTSCAN -j LOG --log-prefix='PORT SCAN DETECTED' --log-level 4

# Add IPs doing port scanning to the blacklist
iptables -A PORTSCAN -m recent --set --name blacklist

# Drop connections from blacklisted IPs (block port scans)
iptables -A PORTSCAN -j DROP

# Reject all traffic (including port scans) from blacklisted IPs
iptables -A INPUT -m recent --name blacklist --rcheck -j REJECT
iptables -A OUTPUT -m recent --name blacklist --rcheck -j REJECT

# Optionally block ICMP Echo Requests (ping) from blacklisted IPs (since it's considered part of the scan)
iptables -A INPUT -p icmp --icmp-type echo-request -m recent --name blacklist --rcheck -j REJECT
iptables -A OUTPUT -p icmp --icmp-type echo-request -m recent --name blacklist --rcheck -j REJECT

iptables -A INPUT -p tcp --dport 80 -m recent --name blacklist --rcheck -j REJECT
iptables -A OUTPUT -p tcp --dport 80 -m recent --name blacklist --rcheck -j REJECT

```

## Nmap from Client
```sh
nmap -p 1-100 10.81.1.211
```

## Try access
```sh
curl http://10.81.1.211
ping 10.81.1.211
nc 10.81.1.211 {port}
```

![Nmap](https://github.com/user-attachments/assets/ced33b93-352c-4d3c-81af-974b9761bff0)

![netcat](https://github.com/user-attachments/assets/4d911f10-9bb7-47be-ab7d-a2a29a973b6a)

![Before](https://github.com/user-attachments/assets/cdb5d8eb-f67c-4d65-b842-bc725583ac34)

![After](https://github.com/user-attachments/assets/2a34223e-86cb-4ff8-9506-29a74d6c1581)

# Soal 7
## iptables configurations (HollowZero)
```sh
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount 3 -j REJECT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

## command to execute
```sh
parallel curl -s http://10.81.1.218 ::: IP-Caesar IP-Burnice IP-Jane IP-Policeboo
```

![parallel_police](https://github.com/user-attachments/assets/e0b78aaf-6ece-43d6-9c92-f8ff862d0d94)

![parallel_caesar](https://github.com/user-attachments/assets/2e9264d2-d9b1-4c9e-91b0-ab763fb7ea3d)

# Soal 8
## iptables configurations (Burnice)
```sh
iptables -t nat -A PREROUTING -p tcp -j DNAT --to-destination 10.81.1.218 --dport 8080
iptables -A FORWARD -p tcp -d 10.81.1.218 -j ACCEPT
```

## Check
```sh
tcpdump -i eth0 host 10.81.1.204 and port 8080
```

![tcp_dump](https://github.com/user-attachments/assets/8d2dbc71-8e0d-473e-9e3f-3069c305b36c)

# Final Mission
## Block Burnice
```sh
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP
```

![ping_to_burnice](https://github.com/user-attachments/assets/ffb63563-e01f-4428-92ae-d63268df3820)

![burnice_ping_Block](https://github.com/user-attachments/assets/676e44bd-ca86-4311-8b47-dcdb1902607e)
