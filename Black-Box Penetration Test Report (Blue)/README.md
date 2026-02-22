# Security Assessment Report  
## SMB Remote Code Execution – MS17-010

---

## 1. Executive Summary

During a controlled black-box security assessment conducted against a Windows host deployed via TryHackMe, a critical Remote Code Execution vulnerability was identified.

The target system, running Microsoft Windows 7, was found vulnerable to MS17-010 (EternalBlue), affecting the SMBv1 protocol implementation.

Successful exploitation allowed unauthenticated remote code execution with NT AUTHORITY\SYSTEM privileges, resulting in full system compromise, credential extraction, and access to sensitive data.

Risk Level: **Critical**

---

## 2. Scope

Target Platform: TryHackMe – Blue  
Operating System: Windows 7 Professional (Service Pack 1)  
Hostname: JON-PC  
Access Level: Unauthenticated network access  
Assessment Type: Black-box  

---

## 3. Vulnerability Overview

Type: Remote Code Execution  
Identifier: MS17-010  
Associated CVE: CVE-2017-0143  
Protocol: SMBv1  
Port: 445/TCP  
Authentication Required: No  
Severity: Critical  
Estimated CVSS: 9.8  

MS17-010 is a memory corruption vulnerability in the SMBv1 server component of Windows systems. The flaw allows specially crafted SMB packets to trigger kernel pool corruption, enabling arbitrary code execution.

The exploit commonly referred to as EternalBlue was publicly weaponized and has been used in global ransomware campaigns.

---
## 4. Technical Details

### 4.1 Service Enumeration

Initial reconnaissance was performed using Nmap:

```bash
sudo nmap -p- -sS -sC -sV --min-rate 5000 -n -Pn -vvv [TargetIP]
```
```python
Nmap scan report for 10.66.156.128
Host is up, received user-set (0.14s latency).
Scanned at 2026-02-21 23:20:02 UTC for 117s
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 126 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Service
49152/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49158/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49159/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

The execution of default NSE scripts revealed additional service configuration details:

```python
Host script results:
| nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:71:57:e4:96:87 (unknown)
| Names:
|   JON-PC<00>           Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   JON-PC<20>           Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   02 71 57 e4 96 87 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32744/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 56461/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 38183/udp): CLEAN (Timeout)
|   Check 4 (port 8172/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 1h11m55s, deviation: 2h40m59s, median: -4s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-02-21T17:21:49-06:00
| smb2-time: 
|   date: 2026-02-21T23:21:49
|_  start_date: 2026-02-21T23:15:51
```

The SMB enumeration revealed that message signing is disabled and SMBv1 is enabled, significantly increasing the attack surface. The host was identified as Windows 7 Professional SP1. This operating system version is historically vulnerable to MS17-010 (EternalBlue) if not properly patched, making SMB a high-priority attack vector.

### 4.2 Vulnerability Confirmation

To validate the suspected exposure identified during enumeration, a targeted vulnerability scan was conducted against the SMB service on port 445.

```bash
sudo nmap -p445 --script=vuln -Pn -vvv [TargetIP]
```

```python
Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
```

The smb-vuln-ms17-010 NSE script identified the host as VULNERABLE, with a HIGH risk factor. This vulnerability allows unauthenticated remote code execution through specially crafted SMB packets.

Other legacy SMB vulnerabilities were tested but returned negative or access denied responses, further narrowing the primary exploitation vector to MS17-010.

Given the confirmed remote code execution vulnerability and the lack of required authentication, exploitation was deemed both feasible and highly reliable.

### 4.3 Exploitation

Following confirmation of MS17-010 exposure, a manual exploitation approach was selected using the AutoBlue-MS17-010 Python implementation. This allowed direct interaction with the exploit logic and payload configuration without relying on automated exploitation frameworks.

Mostrar configuracion de exploit

















