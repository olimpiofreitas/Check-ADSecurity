# Check‑ADSecurity

**PowerShell script to identify common Active Directory security risks**

## 📋 Table of Contents

- [Overview](#overview)  
- [Prerequisites](#prerequisites)  
- [Installation / Setup](#installation--setup)  
- [Usage](#usage)  
- [Checks Performed](#checks-performed)  
- [Sample Output](#sample-output)  
- [Troubleshooting](#troubleshooting)  
- [Contributing](#contributing)  
- [License](#license)  

---

```powershell
===================================================== Starting AD security checks ============================================================================

WARNING: Service 'X' runs from unsafe path: C:\Users\...
WARNING: Non-admin WRITE permission on C:\Windows by DOMAIN\User
WARNING: Scheduled task '\MyTask' runs elevated by DOMAIN\User
HKLM:\...\AlwaysInstallElevated : 1
WARNING: AlwaysInstallElevated enabled on HKLM
Writable PATH directory: C:\Users\Public
GPO audit reporting available
Recent AD events: Event 4720 at 2025-07-25T12:34:56Z for user xpto

======================================================= Checks completed ============================================================================
```



## Overview

`Check‑ADSecurity.ps1` is a PowerShell script designed to identify potential security issues within an Active Directory environment. It examines:

- Services running from unsecured paths  
- Writable permissions on critical folders  
- Scheduled tasks with elevated privileges  
- `AlwaysInstallElevated` registry settings  
- Writable directories in the system `PATH`  
- Group Policy audit settings and recent user‑creation/deletion events

---

## Prerequisites

- Windows machine with **Administrator privileges**  
- PowerShell environment  
- **ActiveDirectory module** available (e.g. via RSAT or on Domain Controllers)  
- *(Optional)* **GroupPolicy module** for GPO reporting  

---

## Installation 

1. Clone or copy the script to your local machine, e.g. `C:\Scripts`  
2. Open **PowerShell as Administrator**  
3. (Optional) Configure script execution policy if restricted:

   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
