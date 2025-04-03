
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched the DeviceFileEvents logs for the string "tor" and found that the user "employee" downloaded and used Tor. As a result, multiple Tor-related files were created and copied to the desktop (torlist.txt).

The event occurred on 2025-04-02 at 02:42:50 UTC.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "Ash-threathunt"  
| where InitiatingProcessAccountName == "employee"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<![image](https://github.com/user-attachments/assets/8c179a95-1eb8-46fb-bd8b-d6a8ae6019d8)
>

---

### 2. Searched the `DeviceProcessEvents` Table

I searched for any ProcessCommandLine events containing the string "tor-browser-windows-x86_64-portable-14.0.1.exe".

According to the logs, on 2025-04-02 at 02:42:35 UTC, an employee on the Ash-ThreatHunt-Lab device executed tor-browser-windows-x86_64-portable-14.0.1.exe from their Downloads folder. The command used triggered a silent installation, bypassing user prompts.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
| where DeviceName contains "Ash-threat"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
<![image](https://github.com/user-attachments/assets/de182c31-e1dc-4506-97af-fbaf77140561)
">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched for any indication that the user "employee" opened the TOR browser.

The logs confirm that the user launched TOR at 2025-04-02T02:36:09 UTC. Additionally, multiple instances of firefox.exe (TOR) and tor.exe were spawned afterward, indicating continued usage.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "Ash-threat"
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/12849469-ed28-4421-a36f-1101b3f0d709)
>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I searched the DeviceNetworkEvents logs for evidence that the user "employee" attempted to establish a connection using Tor ports.

At 2025-04-02T04:13:11 UTC, the user "employee" on the computer "ash-threathunt" successfully initiated a network connection. The connection was made using Firefox and directed to 127.0.0.1 (localhost) on port 9150.

Since port 9150 is commonly used by the Tor network for anonymous internet traffic routing, this suggests that Firefox was configured to use a local Tor service.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "Ash-threat"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/413a951f-624e-46c9-b4a0-5195ea03eaad)
>

---

# Chronological Events  

## Threat Hunt Timeline Report: Tor Browser Usage  

### 2025-04-02T02:36:09.4572291Z  
- Evidence found that the user **employee** opened the **Tor browser**.  
- Multiple instances of **firefox.exe (Tor)** and **tor.exe** were created on the device **Ash-threat**.  
- **Query Used:** `DeviceProcessEvents`  

### 2025-04-02T02:42:35.4896553Z  
- A computer named **ash-threathub-l** executed `tor-browser-windows-x86_64-portable-14.0.9.exe`.  
- The program was launched with the `/S` command, indicating a **silent installation** with no user interaction.  
- **Query Used:** `DeviceProcessEvents`  

### 2025-04-02T02:42:50.3540302Z  
- A user named **"employee"** downloaded and used the **Tor browser**.  
- Several **Tor-related files** were created and copied to the desktop, including `torlist.txt`.  
- **Query Used:** `DeviceFileEvents`  

### 2025-04-02T04:13:11.2923039Z  
- The user **employee** on the computer **ash-threathunt** successfully established a **Tor network connection**.  
- **Firefox** was configured to use **Tor** via **localhost (127.0.0.1) on port 9150**.  
- This suggests that the **Tor network** was actively being used for **anonymous browsing**.  
- **Query Used:** `DeviceNetworkEvents`  

---

## **Summary of Events:**  
- **02:36:09Z** → Tor browser was opened by user **employee**.  
- **02:42:35Z** → Silent installation of **Tor** was performed on **ash-threathub-l**.  
- **02:42:50Z** → **Tor-related files** were created and copied to the desktop.  
- **04:13:11Z** → **Tor network connection** was successfully established using **Firefox** via **port 9150**.  

This investigation confirms that an **employee installed, launched, and actively used the Tor browser** for **anonymous browsing**.  


## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
