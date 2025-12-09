# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/elizabeth-a-h/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

Searched for any file that had the string "tor" in it and discovered what looks like the user "eliz1-user-admin1" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `Tor-Shopping-List.txt` on the desktop. These events began at `2025-12-07T00:19:48.4043439Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "Eliz-1-threat-h"
| where FileName contains "tor"
| where InitiatingProcessAccountName contains "eliz"
| project  Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc 
```

<img width="1438" height="450" alt="image" src="https://github.com/user-attachments/assets/a459753f-4e23-4415-915b-60d2103942b3" />


### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.2.exe". Based on the logs returned, at `2025-12-07T00:54:53.7139443Z`, the user "eliz1-user-admin1" on the "eliz-1-threat-h" device ran the file `tor-browser-windows-x86_64-portable-15.0.2.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where AccountName contains "eliz1-User"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.2.exe"  
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, SHA256
```
<img width="1293" height="181" alt="image" src="https://github.com/user-attachments/assets/db2095a1-941a-44ab-a849-bd26d805f3cd" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "eliz1-user-admin1" actually opened the TOR browser. There was evidence that they did open it at `2025-12-07T00:56:30.6542878Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "eliz-1-threat-h"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browswer.exe")
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc 
```
<img width="1360" height="595" alt="image" src="https://github.com/user-attachments/assets/cd589198-95bb-4803-891b-68ce5d2cd961" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-12-07T00:59:40.5259143Z`,  the user "eliz1-user-admin1" on the "eliz-1-threat-h" device successfully established a connection to the remote IP address `65.65.1.70` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\eliz1-user-admin1\desktop\tor browser\browser\torbrowser\tor\tor.exe`. 
There were several other connections to sites over port 443, 9001 and 9501 .

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "eliz-1-threat-h"
| where ActionType contains "connectionSuccess"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe") 
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443")
| project Timestamp,InitiatingProcessAccountName, DeviceName, ActionType, RemotePort, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1515" height="437" alt="image" src="https://github.com/user-attachments/assets/d6413066-6a3e-4bc6-be84-0270a4f57910" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-12-07T00:19:48.4043439Z`
- **Event:** The user "eliz1-user-admin1" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.2.exe` to the Downloads folder.
- **Action:** User downloaded the Tor Browser installer
- **File Path:** `C:\Users\Eliz1-User-Admin1\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-12-07T00:54:53.7139443Z`
- **Event:** The user "eliz1-user-admin1" executed the file `tor-browser-windows-x86_64-portable-15.0.2.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.2.exe /S`
- **File Path:** `C:\Users\Eliz1-User-Admin1\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-12-07T00:56:30.6542878Z`
- **Event:** User "eliz1-user-admin1" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Eliz1-User-Admin1\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-12-07T00:59:40.5259143Z`
- **Event:** A network connection to IP `65.65.1.70` on port `443` by user "eliz1-user-admin1" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-12-07T01:01:01.2586291Z` - Connected to `176.97.79.138` on port `9001`.
  - `2025-12-07T01:00:16.0572672Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "eliz1-user-admin1" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-12-07T01:24:45.5307885Z`
- **Event:** The user "eliz1-user-admin1" created a file named `Tor-Shopping-List.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Eliz1-User-Admin1\Desktop\Tor-Shopping-List.txt`

---

## Summary

The user "eliz1-user-admin1" on the "eliz-1-threat-h" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "Tor-Shopping-List.txt" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
