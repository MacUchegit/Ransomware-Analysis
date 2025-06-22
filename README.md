![ransomeware-01-1280x640](https://github.com/user-attachments/assets/ffd1c4e6-72bc-4efe-a1a4-d17b74f1cd0c)
Credit : ncmep.org

# 🔐 **Ransomware Detection and Response Walkthrough**

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

### ⚠️ Alert Overview

| Field              | Value                              |
| ------------------ | ---------------------------------- |
| **Event ID**       | 92                                 |
| **Date/Time**      | May 23, 2021, 07:32 PM             |
| **Rule Triggered** | SOC145 - Ransomware Detected       |
| **Host**           | MarkPRD                            |
| **IP Address**     | 172.16.17.88                       |
| **Process Name**   | ab.exe                             |
| **Process Hash**   | `0b486fe0503524cfe4726a4022fa6a68` |
| **Device Action**  | Allowed                            |

---

### 🔍 Pre-Investigation Malware Behavior Insight

Before diving into the full investigation, I ran a quick lookup of the file's **MD5 hash** on **VirusTotal** — and it was flagged by **62 vendors as malicious**, which strongly suggests it's a dangerous file. To better understand how it behaves, I looked deeper into its actions.

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/1b68075f-5369-4d56-b5f4-93559a699b28"/>


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

For a comprehensive breakdown of the behavioral analysis, refer to the full VirusTotal report via the link below:

🔗 [View Full Behavioral Analysis on VirusTotal](https://www.virustotal.com/gui/file/1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2/behavior)


* **🧩 Suspicious Process Chain**

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/76df392f-1a4e-45ec-b4da-c1925f273d33"/>

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

### **Step 1: Is the Malware Quarantined/Cleaned?**

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/195dbccc-6af2-4a6b-9b43-285dee11fd98"/>

* Checked the **EDR panel** for host `MarkPRD` (IP: `172.16.17.88`)

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/5752df5a-b1ac-49d7-9b29-84a8a02db8d5"/>

* Found that the affected host was **not contained**
* Additionally, the SIEM alert overview shows the action status as 'Allowed,' strongly suggesting that the malware execution was not blocked by security controls. 

---

### **Step 2: Analyze the Malware File**

* Inasmuch as I have done a lot of digging earlier, I decided to query the file hash on **VirusTotal** — flagged as **malicious by 62 vendors**
* I identified **flagged contacted IPs** in the “Relations” tab:

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/bbc8affe-8f82-4e19-a77b-48019464f22f"/>

  * `185.125.190.26`
  * `185.125.190.27`
  * `91.199.212.52`

---

### **Step 3: Was the C2 Contacted?**

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/7e253af3-8a06-4df8-b92f-f1b2795f63b1"/>

Checked **Log Management** to see if any **Command & Control (C2)** addresses were reached.

* Inspected raw logs:

---

#### 🔹 **Raw Log 1**

```
Request URL     : http://thuening.de/cgi-bin/uo9wm/
Request Method  : GET
Device Action   : Permitted
Process         : powershell.exe
Parent Process  : BAL_GB9684140238GE.doc
Parent MD5      : ac596d282e2f9b1501d66fce5a451f00
```

#### 🔹 **Raw Log 2**

```
Request URL     : http://nuangaybantiep.xyz
Request Method  : GET
Device Action   : Allowed
Process         : chrome.exe
Parent Process  : explorer.exe
Parent MD5      : 8b88ebbb05a0e56b7dcc708498c02b3e
```

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
  
---

### **Step 5: Close the Alert (True Positive)**

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/851fe38b-0200-4e62-996c-9aec2ef6815f"/>

✅ This alert was **confirmed as a True Positive**.
📝 **Brief Comment**:

> “Confirmed ransomware sample (ab.exe) on host MarkPRD. File allowed to execute. Flagged by 62 AV engines. No C2 connection observed. Recommend immediate containment and system isolation.”

---

### 🛡️ **Recommended Preventive Measures**

* **Apply application whitelisting** — block unknown `.exe` files
* **Educate employees** about phishing and suspicious downloads
* **Keep system patches updated**
* **Implement regular backup strategies** — offline and immutable

---

## ✅ **Conclusion**

This project provided a hands-on look at how ransomware attempts unfold in real-time and how security analysts investigate them. From SIEM alerts to malware analysis and C2 tracking, each step reinforces the importance of **proactive detection** and **incident response readiness**. While this file didn’t complete its full attack chain, the signals were unmistakable — and quick action can make all the difference.
