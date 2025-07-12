# Wazuh SIEM Lab
## Agent Setup & FIM
This project demonstrates how to deploy and configure the Wazuh agent to detect various security threats in a simulated environment. It includes use cases such as File Integrity Monitoring (FIM), brute-force login attempts, SQL injection detection, and more. The goal is to provide a hands-on lab for learning endpoint security, log analysis, and real-time threat detection using Wazuh.


## 1. Agent Deployment

To add an agent to the Wazuh manager:

1. Navigate to `Overview → Agents` in the Wazuh GUI.
2. Click **"Deploy new agent"** and select the operating system of your agent.  
   For Ubuntu, choose **Debian (amd64)**.

## Agent Deployment Screen
<img width="1898" height="899" alt="Image" src="https://github.com/user-attachments/assets/355224c9-343d-4d8a-9d3d-3920a2a30137" />


3. Enter the Wazuh Manager IP address, assign a name to the agent, and copy the installation command provided.

## Agent Setup Command
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/6a3043eb-36b6-43c7-8f7a-10be745b2943" />

4. Paste and run the command in the Ubuntu VM terminal.

## Running Installation Command on Client VM
<img width="957" height="1018" alt="Image" src="https://github.com/user-attachments/assets/fc0c90f9-f1d1-449a-ae4e-375ed647246c" />

5. After installation, enable and start the agent by running:

   ```bash
   sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent

daemon-reload: Reloads systemd manager configuration.

enable: Ensures the agent service starts on boot.

start: Starts the Wazuh agent immediately.

 6. Refresh the Wazuh GUI to confirm the new agent is active.

## Active Agent Confirmation on Dashboard
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/05e217dd-1889-40f3-8b41-4b2999ce7da2" />
Repeat these steps to add any other VM agent of your choice.
For the purpose of this lab, we’re using the Ubuntu agent as demonstrated in the images.  

<br>
<br>
<br>





## 2. 🔍 File Integrity Monitoring (FIM) with Wazuh

As part of this project, I implemented **File Integrity Monitoring (FIM)** using **Wazuh** to detect unauthorized file changes on an Ubuntu agent. FIM is essential for identifying potential security incidents by tracking file creations, modifications, and deletions in real time.

---

### ✅ Enabling FIM on the Ubuntu Agent

To enable File Integrity Monitoring on the Ubuntu agent, I edited the Wazuh agent’s configuration file:

1. I opened the agent configuration file located at:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

## Ossec Configuration- Opening the ossec.conf file]
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/d73dc533-cc44-432d-ac63-19a6a9569778" />

2. Within the `<syscheck>` block, I added the `/root` directory for real-time monitoring. Below is the snippet I inserted:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">/root</directories>
</syscheck>
```

## Monitoring the Root Directory - Added /root to syscheck block
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/16e6ef56-d80e-47aa-8df0-7feb597b14cd" />

> I chose to monitor the `/root` directory because it contains sensitive administrative files. Monitoring this directory helps detect any unauthorized or suspicious activity. Note that proper permissions are required for the Wazuh agent to access this directory.

3. After editing, I saved the file and restarted the Wazuh agent to apply the changes:

```bash
sudo systemctl restart wazuh-agent
```

---

### 🧪 Testing FIM Functionality

To verify that FIM was working as expected, I performed a series of actions in the `/root` directory:

1. **Created a test file:**

```bash
touch sample.txt
```

2. **Modified the file by adding content:**

```bash
echo "This is a modification text" >> sample.txt
```

3. **Deleted the file:**

```bash
rm sample.txt
```

## File creation, modification, and deletion test
<img width="957" height="1018" alt="Image" src="https://github.com/user-attachments/assets/6cdfee0f-7703-4ae5-a7bb-48969b660d00" />

---

### 📊 Viewing FIM Alerts in the Wazuh Dashboard

To confirm that the file changes were detected:

1. I logged into the Wazuh Dashboard.
2. Navigated to:  
   `Modules` → `File Integrity Monitoring`
3. Filtered the alerts and confirmed that the following events were recorded:

- **File creation** (`sample.txt`) — *Rule ID 554*
- **File modification** (Checksum changed) — *Rule ID 550*
- **File deletion** — *Rule ID 554*

## Wazuh Dashboard showing FIM alerts
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/308b0c32-7e91-4501-a390-8eaf3fe3d062" />

---

### ✅ Conclusion

This test confirmed that File Integrity Monitoring was properly configured and actively monitoring sensitive directories on the Ubuntu agent. Wazuh successfully detected and logged all relevant file activity, demonstrating its effectiveness as a real-time security monitoring tool.
<br>
<br>
<br>
<br>




## 3. Automated Threat Blocking with Wazuh Active Response

### 🚫 Detecting and Blocking SSH Brute-force Attacks

Active Response is a powerful feature in Wazuh that enables automatic remediation actions—such as blocking a source IP address—when specific rules or behaviors are detected. This allows security teams to reduce response time and contain threats as they occur.

In this lab, I configured Wazuh to automatically detect and block SSH brute-force attacks using the built-in `firewalldrop` active response command.

---

### ⚙ Step 1: Enabling Active Response on the Wazuh Manager

I began by confirming that Active Response was enabled on the agent by inspecting the `/var/ossec/etc/ossec.conf` file.

Then I added the following configuration to the Wazuh Manager (`ossec.conf`) to trigger firewall rules when SSH brute-force activity is detected:

```xml
<command>
  <name>firewalldrop</name>
  <executable>firewalldrop</executable>
  <expect>srcipt</expect>
</command>

<active-response>
  <command>firewalldrop</command>
  <location>local</location>
  <rules_id>5763</rules_id>
  <timeout>180</timeout>
</active-response>
```

# ossec.conf edit/setup
<img width="867" height="667" alt="Image" src="https://github.com/user-attachments/assets/9ce61dd9-fb45-4691-9fd0-b7bf0251d8ff" />

**Explanation:**

* `firewalldrop`: Executes an IP blocking rule using the host firewall.
* `rules_id: 5763`: Matches SSH authentication failure alerts.
* `timeout: 180`: Blocks the IP for 3 minutes.
* `location: local`: Executes the command on the local agent.

Then restart the Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
```

---

### 🧪 Step 2: Simulating an SSH Brute-force Attack

To test the setup, I simulated an SSH brute-force attack from Kali Linux using Hydra:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
```

# Kali Brute-force Attack
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/60af4b02-b41d-4d1b-a206-c31d837d4980" />

This generated a series of failed SSH login attempts.

---

### 📊 Step 3: Monitoring Alerts and Response in Wazuh

Navigate to:

```
Security Events → Agent → Ubuntu
```

Here’s what I observed:

* ⚠️ Multiple alerts for failed SSH logins (`rule id 5760`)
* ✅ An active response alert:
  `Host blocked by firewalldrop active response with rule id 651`

This confirmed that:

* Wazuh detected the brute-force behavior
* The attacking IP was automatically blocked
* Further login attempts were silently dropped

# Alerts Generated
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/b39aca81-d35d-42ac-bd48-164510e0ba6c" />
<br>

# Alert Details
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/d22bda83-8ecb-447d-8436-acbf18a5fb01" />
<br>

# Alert Details
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/e3b4313e-8c8b-48b4-8c4d-72d9dd627c59" />

---

### ✅ Conclusion

This setup showcases Wazuh’s capability to not only detect malicious activity like brute-force attacks but also respond automatically to reduce impact.

Combining detection and response automates early containment, saving time and reducing risk.

---
<br>
<br>
<br>
<br>

## 4. SQL Attack Monitoring
# 📘 Apache Log Monitoring with Wazuh Agent (Ubuntu Endpoint)

This document outlines the steps I followed to install Apache on an Ubuntu endpoint, configure the Wazuh agent to monitor Apache logs, and emulate an SQL injection attack to validate detection.

---

## 🔧 Step 1: Install Apache Web Server

I began by updating the package list and installing Apache:

```bash
sudo apt update
sudo apt install apache2
```
# Apache2 Installation
<img width="957" height="1018" alt="Image" src="https://github.com/user-attachments/assets/6834d01a-1192-40af-b531-4be4c3d7b462" />

---

## 🔐 Step 2: Configure the Firewall (If Enabled)

Since UFW (Uncomplicated Firewall) was enabled, I allowed access to web traffic:

```bash
sudo ufw app list
sudo ufw allow 'Apache'
sudo ufw status
```

# Firewall Configuration
<img width="958" height="1019" alt="Image" src="https://github.com/user-attachments/assets/0c2abb44-8aa4-4a39-9685-a1bbf918b9d6" />
.

---

## ✅ Step 3: Verify Apache Is Running

To ensure the web server was running:

```bash
sudo systemctl status apache2
```


I verified the default Apache landing page by opening the following URL in a browser:


http://192.168.0.108


```bash
curl http://192.168.0.108
```

# Apache Page 
<img width="957" height="1018" alt="Image" src="https://github.com/user-attachments/assets/4fb83a92-ef1a-4da8-8fc3-4f0a07210e47" />

---

## 📄 Step 4: Configure Wazuh Agent for Apache Log Monitoring

I edited the Wazuh agent configuration file to include monitoring for Apache logs:

```bash
sudo nano /var/ossec/etc/ossec.conf
```


Inside the `<ossec_config>` block, I added the following:

xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>

# Apache ossec configuration on Agent
<img width="957" height="1018" alt="Image" src="https://github.com/user-attachments/assets/bb2fb32e-c1d6-4827-9729-9cca1d02cb6b" />

Then, I restarted the Wazuh agent to apply the changes:

```bash
sudo systemctl restart wazuh-agent
```


---

## 🧪 Step 5: Simulate an SQL Injection Attack

To test Wazuh’s ability to detect web-based attacks, I simulated a simple SQL injection from my Kali VM:

```bash
curl -XGET "http://192.168.0.108/users/?id=SELECT+*+FROM+users"
```
# SQL Attack Simulation 
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/dc78c54f-bac0-4bb7-8c3c-f43fd6beddad" />

---

## 📊 Step 6: Review Alerts in Wazuh Dashboard

After executing the simulated attack, I checked the Wazuh dashboard for alerts.

> ✅ *Result:* An alert was triggered with **Rule ID 31103**, indicating a detected SQL injection attempt.

# Alerts Generated on Wazuh Dashboard
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/f0da38e7-e136-4067-b9ba-5c33bf462013" />


# Alerts Details
<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/97ae8069-0002-4ce8-85de-7d4d9c9321ac" />

<img width="1920" height="1020" alt="Image" src="https://github.com/user-attachments/assets/7de76789-ab9f-45ab-a5c0-38117276d5bc" />

---

## ✅ Conclusion

This setup confirms that Wazuh can successfully monitor Apache logs and generate alerts for suspicious activity such as SQL injection. By enabling log monitoring on the Ubuntu endpoint and validating the alert response, I ensured that my Wazuh deployment is capable of detecting web application attacks.

