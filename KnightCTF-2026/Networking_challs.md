# Knight Blog CTF - Network Forensics Writeup

> **Category:** Network Forensics  
> **Tools Used:** Wireshark/tshark, Kali Linux

---

## Scenario

A mid-sized e-learn company "Knight Blog" recently detected suspicious network activity on their infrastructure. As the lead forensic analyst for the Knight Security Response Team, we've been called in to investigate. The IT team provided packet captures taken at different stages of what appears to be a coordinated cyber attack. Our mission is to analyze these captures, trace the attacker's footsteps, and uncover the full scope of the breach.

---

# Challenge 1: Reconnaissance

| Property | Value |
|----------|-------|
| **Difficulty** | Easy |
| **Flag Format** | `KCTF{number}` |

## Challenge Description

> Our IDS flagged some suspicious scanning activity in the first capture. The attacker was probing our network to identify potential entry points. Analyze the traffic and determine how many ports were found to be open on the target system.

## Analysis

### 1. Identify Scanning Activity
The first step is to identify the source of the attack. Port scans typically involve sending a large number of **SYN** packets to various ports on a target IP.

Using `tshark`, we filtered for SYN packets that did not have the ACK flag set (indicating a connection initiation attempt) and looked for the most frequent source-destination pairs.

**Command:**
```bash
tshark -r pcap1.pcapng -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -nr | head -n 5
```

**Output:**
```
65558 192.168.1.104   192.168.1.102
    7 192.168.1.110   192.168.1.102
    ...
```

**Findings:**
- **Attacker IP:** `192.168.1.104` (Source of massive SYN flood)
- **Target IP:** `192.168.1.102` (Victim receiving packets)

### 2. Identify Open Ports
To find which ports were actually open, we need to look for successful responses from the target. When a port is open, the server responds to a SYN packet with a **SYN-ACK** packet.

We filtered for traffic where:
- Source is the Target (`192.168.1.102`)
- Destination is the Attacker (`192.168.1.104`)
- TCP Flags are **SYN=1** AND **ACK=1**

**Command:**
```bash
tshark -r pcap1.pcapng -Y "ip.src==192.168.1.102 && ip.dst==192.168.1.104 && tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e tcp.srcport | sort | uniq
```

**Output:**
```
22
80
```

This confirms that two ports responded as open: **22 (SSH)** and **80 (HTTP)**.

## Flag
The flag requires the number of open ports found.

**Flag:** `KCTF{2}`

---

# Challenge 2: Gateway Identification

| Property | Value |
|----------|-------|
| **Points** | 480 |
| **Flag Format** | `KCTF{vendor_name}` |

## Challenge Description

> During the initial reconnaissance, the attacker gathered information about the network infrastructure. We need to identify the vendor of the network device acting as the default gateway in this capture.

## Analysis

### 1. Identify Default Gateway IP
In a standard local network configuration (subnet `192.168.1.0/24`), the default gateway is typically assigned the first usable IP address, which is `192.168.1.1`.

### 2. Retrieve Gateway MAC Address
To find the vendor, we first need the MAC address of the gateway. We can inspect **ARP** (Address Resolution Protocol) traffic, which maps IP addresses to physical MAC addresses.

We filtered for ARP replies (`arp.opcode==2`) to see the MAC addresses of devices on the network.

**Command:**
```bash
tshark -r pcap1.pcapng -Y "arp.opcode==2" -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac -e eth.src_resolved | sort | uniq
```

**Output:**
```
192.168.1.1     88:bd:09:38:d7:a0   NetisTechnol_38:d7:a0
192.168.1.102   08:00:27:0e:62:25   PCSSystemtec_0e:62:25
...
```

**Findings:**
- **Gateway IP:** `192.168.1.1`
- **Gateway MAC:** `88:bd:09:38:d7:a0`
- **Wireshark OUI Resolution:** `NetisTechnol`

### 3. Determine Vendor Name
The OUI (Organizationally Unique Identifier) `88:bd:09` corresponds to **Netis Technology**. The flag format requires the vendor name.

## Flag
The vendor is Netis Technology.

**Flag:** `KCTF{Netis_Technology}`
