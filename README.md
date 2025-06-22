## 🔐 **Ransomware Detection and Response Walkthrough**

**Using Let’s Defend SIEM for Hands-on Threat Investigation**

In this cybersecurity analysis project, I conducted a full investigation of a **realistic ransomware attack** scenario using the **Let’s Defend SIEM platform**. The alert flagged a suspicious process (`ab.exe`) on host `MarkPRD`, with the device action marked as **Allowed**, signaling that the malicious file was **not contained**.

### 🎯 **Project Purpose**

To simulate the role of a **Security Analyst** in detecting, analyzing, and responding to a ransomware alert in a live SOC environment — helping organizations **understand the impact**, **trace behavior**, and **respond swiftly** to limit damage.

---

### 🧰 **Environment & Tools Used**

* **SIEM Tool**: Let’s Defend
* **EDR (Endpoint Detection & Response)**
* **Threat Intelligence Services**:

  * [VirusTotal](https://virustotal.com)
  * AnyRun (sandbox)
  * URLScan, HybridAnalysis, URLHaus

---

### 📌 **Initial Alert Overview**

* **Event ID**: 92
* **Timestamp**: May 23, 2021 — 07:32 PM
* **Alert Rule**: `SOC145 - Ransomware Detected`
* **Host**: MarkPRD (`172.16.17.88`)
* **Suspicious File**: `ab.exe`
* **MD5 Hash**: `0b486fe0503524cfe4726a4022fa6a68`
* **Action Taken**: Allowed (not quarantined)

---

### 🔍 Pre-Investigation Malware Behavior Insight

Before diving into the full investigation, I ran a quick lookup of the file's **MD5 hash** on **VirusTotal** — and it was flagged by **62 vendors as malicious**, which strongly suggests it's a dangerous file. To better understand how it behaves, I looked deeper into its actions.

Based on the behavior, this file strongly resembles **ransomware**.

---

### 🧪 What is Ransomware? *(Explained simply)*

> Ransomware is a type of malicious software that **locks your files or entire computer** and demands money (a ransom) to unlock them. It encrypts your important documents — like photos, business files, and emails — and won’t let you access them until you pay. Some ransomware also tries to delete system backups so you can’t recover your files without paying.

---

### ⚙️ Malware Behavior Overview (Easy Breakdown)

Here’s a simplified breakdown of what this malware was observed doing:

* **🧭 Scans Drives to Spread Itself**
  It checks all system drives (like A:\ to Z:) — often used to find and infect **USB drives** or external storage.

* **🛠️ Hides and Stays Active via WMI & Task Scheduling**
  It uses **WMI** (a Windows feature for managing system tasks) to:

  * Create **hidden processes**
  * Set up **scheduled tasks** so it can auto-run quietly

* **🧩 Suspicious Process Chain**
  The malware starts with a process called `taskhost.exe` which:

  * Launches repeated commands like `wmic SHADOWCOPY DELETE` and `vssadmin Delete Shadows` to **delete backups**
  * Uses processes like `cmd.exe` and `conhost.exe` repeatedly — a sign of **automated or scripted attack behavior**

* **🧹 Disables Backup & Recovery**
  It deletes system restore points using:

  * `vssadmin`, `wmic`, and `wbadmin`
  * Then uses `bcdedit` to **disable recovery options**, so you can’t undo the damage

* **🎭 Runs Under Legit Windows Services**
  Executes its malicious payload using trusted processes like:

  * `svchost.exe`, `vssvc.exe`, and `wmiprvse.exe`
    → This helps it **hide in plain sight** and avoid detection

---

Now that I understood the nature of the file, I moved on with the structured analysis using the Let’s Defend SIEM platform.

## 🕵️‍♂️ **Walkthrough: My Investigation Process**

### **Step 1: Is the Host Quarantined?**

* Checked the **EDR panel** for host `MarkPRD` (IP: `172.16.17.88`)
* Found that the file `ab.exe` was **not quarantined**
* Status: ❌ *Still active and allowed to run on the system*

---

### **Step 2: Analyze the Malware File**

* Queried the file hash on **VirusTotal** — flagged as **malicious by 62 vendors**
* Identified **contacted IPs** in the “Relations” tab:

  * `185.125.190.26`
  * `185.125.190.27`
  * `91.199.212.52`

---

### **Step 3: Was the C2 Contacted?**

Checked **Log Management** to see if any **Command & Control (C2)** addresses were reached.

* Inspected raw logs:

  * `http://thuening.de/cgi-bin/uo9wm/` accessed by `powershell.exe`
  * `http://nuangaybantiep.xyz` accessed by `chrome.exe`
* These were **not linked to the malware’s C2**, so no callback occurred.
  ✔️ *The malware didn’t communicate back to the attacker — yet.*

---

### **Step 4: Record IOCs (Indicators of Compromise)**

> Documenting IOCs is critical — it helps detect future attacks, write YARA/Sigma rules, and keep threat intel updated.

* **File Hash**: `0b486fe0503524cfe4726a4022fa6a68`
* **Malicious File**: `ab.exe`
* **Related IPs**: `185.125.190.26`, `185.125.190.27`, `91.199.212.52`
* **Processes Observed**: `powershell.exe`, `chrome.exe`

---

### **Step 5: Close the Alert (True Positive)**

✅ This alert was **confirmed as a True Positive**.
📝 **Brief Comment**:

> “Confirmed ransomware sample (ab.exe) on host MarkPRD. File allowed to execute. Flagged by 62 AV engines. No C2 connection observed. Recommend immediate containment and system isolation.”

---

### 🛡️ **Recommended Preventive Measures**

* **Enable real-time threat prevention & auto-containment** in EDR
* **Apply application whitelisting** — block unknown `.exe` files
* **Educate employees** about phishing and suspicious downloads
* **Keep system patches updated**
* **Implement regular backup strategies** — offline and immutable

---

## ✅ **Conclusion**

This project provided a hands-on look at how ransomware attempts unfold in real-time and how security analysts investigate them. From SIEM alerts to malware analysis and C2 tracking, each step reinforces the importance of **proactive detection** and **incident response readiness**. While this file didn’t complete its full attack chain, the signals were unmistakable — and quick action can make all the difference.
