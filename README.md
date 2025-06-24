# VulnScope: Cyber Threat Intelligence Dashboard 🛡️

**VulnScope** is a web-based Cyber Threat Intelligence (CTI) Dashboard that enables real-time threat analysis of IP addresses and domain names using open-source threat intelligence feeds. Designed with simplicity and clarity, it provides structured threat insights, tagging capabilities, visual threat metrics, and exportable scan reports.

---

## 🛡️ Overview
The Cyber Threat Intelligence (CTI) Dashboard is a sophisticated, real-time, and interactive platform meticulously designed to aggregate, correlate, and analyze threat intelligence feeds sourced from diverse open CTI repositories. This comprehensive system empowers security analysts and incident response teams to continuously monitor the evolving threat landscape, validate potentially malicious indicators, and derive meaningful, actionable insights through intuitive and visually compelling dashboards. By consolidating fragmented threat data into a unified and easily navigable interface, the CTI Dashboard significantly enhances an organization’s situational awareness, facilitates timely threat detection, and supports informed, proactive decision-making to strengthen overall cybersecurity posture.

---

## 🎯 Objective
The primary objective is to design and implement a robust, real-time dashboard that seamlessly consolidates threat intelligence data from a multitude of reputable sources. This integrated platform aims to empower cybersecurity professionals with enhanced visibility into the threat landscape, enabling continuous, proactive monitoring and facilitating swift, informed responses to emerging cyber threats. By providing timely, comprehensive, and actionable intelligence, the dashboard supports organizations in fortifying their security posture and mitigating potential risks more effectively.

---

## 🧰 Tech Stack

| Layer        | Technology               |
|--------------|---------------------------|
| Framework    | Flask / Django (Python) |
| Frontend     | HTML, CSS, JavaScript, Chart.js |
| Backend      | Python           |
| CTI API      | VirusTotal Public API     |
| Storage      | JSON-based scan logs      |
| Reporting    | jsPDF, html2canvas        |

---

## 📌 Features

- 🔎 **Live Threat Lookup**: Scan IPs/domains for threat intelligence using VirusTotal.
- 📊 **Threat Metrics Visualization**: Donut chart shows malicious/harmless/undetected ratio.
- 🕓 **Historical Lookup Tracking**: Stores scan logs with timestamps.
- 🏷️ **Tagging System**: Label each scan as *Safe*, *Suspicious*, or *Malicious*.
- 📄 **PDF Report Export**: Export scan results with visual data in printable format.
- 📱 **Responsive Design**: Optimized for desktop and mobile devices.

---

## 🗂️ Project Structure

```bash
VulnScope/
|---dashboard/
|---|---static/
|---|---|---style.css
|---|---templates/
|---|---|---index.html
|---|---app.py
|---reports/
|---|---lookup_log.json
|---|---scan_log.json
|---|---tags.json
|---requirements.txt
```
---

## 🧭 Project Workflow

### 1️⃣ Data Collection
- Integrate with VirusTotal API to pull threat data.
- Schedule periodic API requests to ensure continuous feed updates.
- Store retrieved data securely in MongoDB.

### 2️⃣ Data Display
Design UI components to display:
- Threat Levels (e.g., Low, Medium, High)
- IOCs including malicious IPs, URLs, file hashes
- Historical trends and recent alerts

### 3️⃣ User Input & Verification
- Implement forms for users to submit IP addresses or domain names.
- Query APIs to check reputation and threat scores for input indicators.
- Return verification results with threat context.

### 4️⃣ Data Visualization
Plot metrics such as:
- Number of threats detected over time
- Top malicious IPs/domains
- Geographical distribution (optional)

Use libraries like Chart.js for dynamic, responsive charts.

### 5️⃣ Tagging & Export
- Enable tagging threats by category, severity, or source.
- Allow exporting of dashboard data in CSV/JSON/PDF format for reporting.

---


## 🚀 Installation & Setup

### 🔹 Prerequisites
- Python 3.x
- pip
- API key for VirusTotal

### 🔹 Clone the Repository
```bash
git clone https://github.com/priyanshipawar05/VulnScope_CTI_dashboard.git
cd VulnScope
```

### 🔹 Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 🔹 Install Dependencies
```bash
pip install -r requirements.txt
```

### 🔹 Configure API Keys
Create a `.env` file:
```env
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_API_KEY
```

### 🔹 Run the Application
```bash
flask run  # or python manage.py runserver for Django
```

## 🔍 Usage
- Access the dashboard at [http://localhost:5000](http://localhost:5000).
- View real-time threat feeds on the main page.
- Use the Lookup feature to check any suspicious IP/domain.
- Explore visualizations for threat trends and statistics.
- Tag and export relevant data for reports or compliance.

---

## 📦 Deliverables
- A fully functional real-time Cyber Threat Intelligence Dashboard
- Capability to lookup threats and verify user-supplied indicators
- Intuitive visualizations and trend analysis
- Tagging and data export functionalities

---

## 📈 Future Improvements
- Add user authentication and role-based access.
- Integrate additional CTI sources.
- Include notification and alerting mechanisms.
- Deploy using Docker and secure with HTTPS.


## 🎓 Learning Outcomes
By working on this Cyber Threat Intelligence (CTI) Dashboard project, learners will:

✅ Understand the fundamentals of threat intelligence — Learn how to collect, process, and interpret threat feeds from reputable CTI sources.
✅ Gain experience with APIs — Integrate and interact with public APIs like VirusTotal for real-time threat data.
✅ Design interactive dashboards — Use JavaScript libraries (e.g., Chart.js) to create dynamic, user-friendly data visualizations.
✅ Implement user input and validation — Build secure forms for verifying indicators and handling user queries.
✅ Enhance reporting and compliance understanding — Enable data export and tagging, simulating real-world security operations workflows.
✅ Practice deployment and security best practices — Prepare for production deployment, API key management, and securing sensitive information.

This project strengthens practical knowledge in cybersecurity operations, full-stack development, API integration, and data visualization, making it an excellent hands-on learning experience for aspiring security analysts and developers.


Happy Threat Hunting! ⚔️
