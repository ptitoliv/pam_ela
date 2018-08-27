# pam_ela
pam_ela is a PAM module which does Ethernet Link Allocation (ELA)

# Introduction
pam_ela is a PAM session module which creates a dedicated network namespace for a logged user on session creation. On session opening, pam_ela executes the following operations :
 * Creates a dedicated network namespace
 * Creates a VETH pair (Name and MAC address are generated using UID)
 * Attaches a VETH peer on the namespace
 * Attaches the other VETH peer on the main network namespace and enslaves it on the br0 bridge
  
# Compilation

``` 
make && make install 
```

# Installation

Edit your pam target and add the following line on session block

```
session    optional     pam_ela.so
```

# Disclaimer
pam_ela is a simple PoC written by a guy who is a terrible C developper. So just use it for test purpose. I won't guarantee that the code is safe and/or secure.

# Example

In this example, there is a dedicated DHCP server running listenning on br0 bridge.

```
$ ssh user_ns@192.168.1.64
user_ns@192.168.1.64's password:
Last login: Sun Aug 26 16:30:42 2018 from 192.168.1.1
[user_ns@test ~]$ ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: veth_1001_0@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:11:22:33:3e:09 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.10.10.16/24 brd 10.10.10.255 scope global dynamic veth_1001_0
       valid_lft 86398sec preferred_lft 86398sec
    inet6 fe80::211:22ff:fe33:3e09/64 scope link
       valid_lft forever preferred_lft forever
```
