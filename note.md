# KJK Firewall Implementation Notes

---

## A. Network Configuration IP Address

### 1. Router Interfaces & Gateways

| **Device Name**      | **Role**         | **Interface** | **IP Address**   | **Subnet Mask** | **Description**                   |
| -------------------- | ---------------- | ------------- | ---------------- | --------------- | --------------------------------- |
| **Edge Router**      | Internet Gateway | `ether1`      | _DHCP (Dynamic)_ | -               | Connection to Internet (GNS3 NAT) |
|                      |                  | `ether2`      | **10.0.0.1**     | /30             | Uplink to Core Firewall           |
| **Firewall**         | Core Security    | `ether1`      | **10.0.0.2**     | /30             | Uplink to Edge Router             |
|                      |                  | `ether2`      | **10.1.40.1**    | /30             | Downlink to **Admin** Router      |
|                      |                  | `ether3`      | **10.1.20.1**    | /30             | Downlink to **Akademik** Router   |
|                      |                  | `ether4`      | **10.1.30.1**    | /30             | Downlink to **Riset/IoT** Router  |
|                      |                  | `ether5`      | **10.1.10.1**    | /30             | Downlink to **Mahasiswa** Router  |
|                      |                  | `ether6`      | **10.1.50.1**    | /30             | Downlink to **Guest** Router      |
|                      |                  | `ether7`      | **10.1.60.1**    | /30             | Downlink to **DMZ** Router        |
| **Admin Router**     | Trusted Zone     | `ether1`      | **10.1.40.2**    | /30             | Uplink to Firewall                |
|                      |                  | `ether2`      | **10.20.40.1**   | /24             | **Gateway for Admin PCs**         |
| **Akademik Router**  | Staff Zone       | `ether1`      | **10.1.20.2**    | /30             | Uplink to Firewall                |
|                      |                  | `ether2`      | **10.20.20.1**   | /24             | **Gateway for Staff PCs**         |
| **Riset Router**     | IoT Zone         | `ether1`      | **10.1.30.2**    | /30             | Uplink to Firewall                |
|                      |                  | `ether2`      | **10.20.30.1**   | /24             | **Gateway for IoT Devices**       |
| **Mahasiswa Router** | Student Zone     | `ether1`      | **10.1.10.2**    | /30             | Uplink to Firewall                |
|                      |                  | `ether2`      | **10.20.10.1**   | /22             | **Gateway for Students**          |
| **Guest Router**     | Public Zone      | `ether1`      | **10.1.50.2**    | /30             | Uplink to Firewall                |
|                      |                  | `ether2`      | **10.20.50.1**   | /22             | **Gateway for Guests**            |
| **DMZ Router**       | Server Zone      | `ether1`      | **10.1.60.2**    | /30             | Uplink to Firewall                |
|                      |                  | `ether2`      | **10.20.60.1**   | /24             | **Gateway for Public Servers**    |

### 2. Client Network Summary

This table will explain the **CIDR** allocations.

| **Department**  | **Network Address** | **Prefix** | **Usable Host Range** | **Gateway IP** |     |
| --------------- | ------------------- | ---------- | --------------------- | -------------- | --- |
| **Admin**       | `10.20.40.0`        | `/24`      | `.2` to `.254`        | `10.20.40.1`   |     |
| **Akademik**    | `10.20.20.0`        | `/24`      | `.2` to `.254`        | `10.20.20.1`   |     |
| **Riset & IoT** | `10.20.30.0`        | `/24`      | `.2` to `.254`        | `10.20.30.1`   |     |
| **DMZ Servers** | `10.20.60.0`        | `/24`      | `.2` to `.254`        | `10.20.60.1`   |     |
| **Mahasiswa**   | `10.20.8.0`*        | `/22`      | `8.1` to `11.254`     | `10.20.10.1`   |     |
| **Guest**       | `10.20.48.0`*       | `/22`      | `48.1` to `51.254`    | `10.20.50.1`   |     |

*Note: For the /22 networks, the IP address `.10.1` and `.50.1` fall comfortably inside the valid range of their respective blocks.

---

## B. Network Defense Layers

### 1. Perimeter Defense (Edge Router)

**Security Function:** _Attack Surface Reduction & Obfuscation._
- **NAT (Masquerade):**
    - **Function:** It hides your entire internal structure (`10.20.x.x`) behind a single public IP.
    - **Security Value:** An attacker on the internet cannot route directly to your Admin PC or IoT devices. They can only see the Edge Router.
- **Management Plane Hardening (Input Chain):**
    - **Function:** You configured the Edge Router to **DROP** all Telnet/SSH attempts from the Internet and from Unauthorized Internal Zones (Guests/Students).
    - **Security Value:** This protects the **Integrity** of the network. Even if a student guesses your password, they cannot even get the login prompt to type it in.

### 2. Core Segmentation (Firewall)

**Security Function:** _Traffic Control & Isolation._
This is the "Brain" of your security. It implements a **Positive Security Model** (Default Drop). Instead of trying to list all "Bad" things (which is impossible), you blocked _everything_ and only listed the "Good" things.
- **Stateful Inspection:**
    - **Function:** The rule `connection-state=established,related action=accept`.
    - **Security Value:** The firewall remembers who started a conversation. If a Student asks for a website (Outbound), the firewall remembers this and automatically lets the website's reply (Inbound) come back. But if a hacker tries to _start_ a connection to the Student, it is dropped.
- **Lateral Movement Prevention:**
    - **Function:** The rule `DROP All Other Forward`.
    - **Security Value:** This prevents a compromised device in one department (e.g., a virus on a Student Laptop) from spreading to other departments (like the Admin Server). This preserves **Confidentiality**.

### 3. Zone-Based Security Policies

**Security Function:** _Least Privilege Access._
You divided the network into "Zones" based on trust levels.

| **Zone**            | **Trust Level** | **Security Policy** | **Functionality**                                                                                                                                               |
| ------------------- | --------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Admin**           | **High**        | "God Mode"          | **Availability:** Admins need to reach everywhere to fix problems.                                                                                              |
| **Akademik**        | **Medium**      | Selective Access    | **Operational Security:** Staff can pull data from IoT sensors (Riset) to do their jobs, but cannot touch Admin data (Confidentiality).                         |
| **IoT/Riset**       | **Medium**      | Selective Access    | **Functionality:** Devices can report data to servers, but are blocked from sensitive networks.                                                                 |
| **Mahasiswa/Guest** | **Zero**        | Internet Only       | **Isolation:** These are treated as "Hostile." They are granted internet access (Availability) but are strictly firewalled from the Intranet (Confidentiality). |
| **DMZ**             | **Isolated**    | Public Facing       | **Containment:** If a Web Server in the DMZ gets hacked, the hacker is trapped. They cannot use the server as a stepping stone to jump into the Admin network.  |

### 4. Resilience & Availability (DoS Defense)

**Security Function:** _Resource Protection._
- **The "Drop" Logic:**
    - **Function:** As proven in your Flood Test, the Firewall creates a hard wall.
    - **Security Value:** When the Mahasiswa network launched a Traffic Surge (DoS), the firewall absorbed the packets at the gateway level. This ensured that the **Admin Network remained Available**. The attack consumed bandwidth on the _link_, but it did not crash the _target servers_.

---

**Summary of the Network Defense Layer**

> *"The configured network ecosystem functions as a **Zero-Trust inspired architecture**. It utilizes **Network Segmentation** to isolate broadcast domains and a **Stateful Core Firewall** to enforce granular Access Control Lists (ACLs).
> 
> The system ensures **Confidentiality** by blocking unauthorized lateral movement (e.g., Student to Admin), preserves **Integrity** by hardening the management plane of network devices against internal and external tampering, and maintains **Availability** by filtering malicious traffic surges (DoS) before they reach critical servers."*

---

## C. Network Defense Layers Testing

### 1. Perimeter Defense Testing

#### a. NAT (Network Address Translation)

1. Get the Edge Router's WAN IP by running the command below on **Edge Router**

```bash
/ip address print where interface=ether1
```

![edge-router-wan-ip](images/edge-router-wan-ip.png)

2. Generate traffic from the **Admin Router** 

```bash
ping 8.8.8.8
```

![admin-generate-traffic](images/admin-generate-traffic.png)

or use this instead:

```bash 
ping 8.8.8.8 src-address=10.20.40.1
```

3. Look at the Connection Table on **Edge Router**

```bash
/ip firewall connection print detail where protocol=icmp
```

![edge-router-admin-traffic-detail](images/edge-router-admin-traffic-detail.png)

![edge-router-admin-traffic-detail-2](images/edge-router-admin-traffic-detail-2.png)

- We can know if it had worked if 

--- 

Other than the 3rd step from above, we can also use this method: 

```bash
/ip firewall nat print stats
```

- Look at the **masquerade** rule
- If the **Packets** column is **increasing** while you run the ping from the Admin Router, **NAT is working**.

![edge-router-network-stats](images/edge-router-network-stats.png)

![edge-router-network-stats](images/edge-router-network-stats-2.png)

---

## Firewall Configurations & Testing

### 1. Firewall Rules 

### 2. Firewall Testing

#### a. IoT & Riset

1. **Testing Ping Rate Limit**

```bash
ping 10.20.20.1 src-address=10.20.30.1 size=1200 count=100 interval=0.05
```

- **Attack Speed:** 20 pps.
- **Limit:** 5 pps.
- **Result:** **Heavy Loss (~75%)**.

#### b. Akademik

1. Testing Ping Rate Limit

```bash 
ping 10.20.30.1 src-address=10.20.20.1 size=1200 count=100 interval=0.05
```

- **Attack Speed:** 20 pps.
- **Limit:** 15 pps.
- **Result:** **Light/No Loss (~0-25%)**.

#### c. Admin

1. Testing Ping Rate Limit

```bash
ping 10.20.20.1 src-address=10.20.40.1 size=1200 count=100 interval=0.05
```

- **Attack Speed:** 20 pps.
- **Limit:** None.
- **Result:** **0% Loss**

