# threat-hunting-scenario-tor
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Chibiaiko/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Investigated the DeviceFileEvents table for ANY files that had the string “tor” in it and discovered what appears the users “alexiscyberrange” downloaded a tor installer, and that resulted into many tor-realated files being copied to the desktop and created a file called “tor-shopping-list.txt” onto the desktop at 2025-10-13T03:02:06.7833307Z. These events began at: 2025-10-13T02:41:39.0462467Z.


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "alexis"
| where InitiatingProcessAccountName contains "alexiscyberrange"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-10-13T02:41:39.0462467Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="710" height="390" alt="DeviceFileEvents 1" src="https://github.com/user-attachments/assets/17eb6a9f-070f-44c9-89f6-d7a7d268dc47" />

---

### 2. Searched the `DeviceProcessEvents` Table

Investigated the DeviceProcessEvents table for ANY ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.8.exe”. Based on the longs returned, at 2025-10-13T02:41:39.4774816Z, the user alexis-onboard on the system alexiscyberrange ran a downloaded file called tor-browser-windows-x86_64-portable-14.5.8.exe. This action created a new process, launching the Tor Browser, a tool commonly used to browse the internet privately and hide online activity — suggesting the user was initiating an anonymous browsing session.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName contains "alexis"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="852" height="70" alt="DeviceProcessEvents 2" src="https://github.com/user-attachments/assets/729185a0-a6ff-4ed8-867a-001cc0305e05" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Did a deeper dive into the DeviceProcessEvents table for any indication that the user “alexiscyberrange” had opened/accessed the tor browser. Upon the investigation the browser had been opened/accessed by the user at 2025-10-13T02:46:11.3192101Z. There were several other instances of firefox.exe(tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "alexis"
| where FileName has_any ("tor.exe", "firefox.exe", "torbrowser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="842" height="206" alt="DeviceProcessEvents 3" src="https://github.com/user-attachments/assets/e3917b0a-7b55-48f1-9425-ce97ee38445c" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Investigated the DeviceNetworkEvents table for any indication if the tor browser was used to establish a connection using any of the known tor ports.
At 2025-10-13T02:48:13.5820676Z, the computer alexis-onboard, used by alexiscyberrange, successfully connected to the remote IP address 217.154.210.223 over port 9001 — a port commonly associated with the Tor network. The connection was made by the process tor.exe, located in the Tor Browser folder on the user’s desktop, indicating that the Tor service was actively connecting to the Tor network. 
There were other connections over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "alexis"
| where InitiatingProcessAccountName != "system"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="899" height="211" alt="DeviceNetworkEvents 4" src="https://github.com/user-attachments/assets/60ff83d5-2cd6-410b-948f-e385bec488c7" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-10-13T02:41:39.0462467Z`
- **Event:** The user "alexiscyberrange" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.8.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\alexiscyberrange\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** ` 2025-10-13T02:41:39.046253Z`
- **Event:** The user "alexiscyberrange" executed the file `tor-browser-windows-x86_64-portable-14.5.8.exe`.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.8.exe`
- **File Path:** `C:\Users\alexiscyberrange\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-10-13T02:46:27.9207531Z`
- **Event:** User "alexiscyberrange" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\alexiscyberrange\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-10-13T02:48:13.5820676Z`
- **Event:** A network connection to IP `217.154.210.223` on port `9001` by user "alexiscyberrange" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\alexiscyberrange\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-10-13T02:48:10.2301337Z` - Connected to `46.226.106.182` on port `443`.
  - `2025-10-13T02:46:57.6887649Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "alexiscyberrange" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-10-13T03:02:06.7833307Z`
- **Event:** The user "alexiscyberrange" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\alexiscyberrange\Desktop\tor-shopping-list.txt`

---

## Summary

The user "alexiscyberrange" on the "Alexis-Onboard-MDE-Lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `Alexis-Onboard-MDE-Lab` by the user `alexiscyberrange`. The device was isolated, and the user's direct manager was notified.

---
