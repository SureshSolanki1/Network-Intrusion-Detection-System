# Network-Intrusion-Detection-System
A real-time Network Intrusion Detection System built with TypeScript, Wireshark and React !!!

# 🔐 Network Intrusion Detection System (NIDS)

A real-time **Network Intrusion Detection System** (NIDS) built using **TypeScript**, **React**, and **Wireshark** CSV exports. The system simulates live traffic analysis, detects network threats using custom rule-based logic, and displays alerts with risk analysis on an interactive dashboard.

---

## 🧠 Project Overview

This tool is designed to analyze `.csv` files exported from **Wireshark**, detect threats like port scans or brute force attacks, and raise alerts based on predefined logic. It simulates packet-level inspection, evaluates risk scores, and provides a comprehensive UI to monitor suspicious activity.

---

## ✨ Features

- 📥 **CSV Uploads from Wireshark**
- 🚨 **Real-Time Intrusion Detection**
- 📊 **Threat & Risk Analysis Dashboard**
- 📄 **Detailed Packet & Alert View**
- 🧩 **Custom Detection Rules**
- 📈 **Graphical Visualizations with Recharts**
- 💡 Built with modern tech: **React**, **TypeScript**, **Tailwind CSS**

---

## 🛠 Tech Stack

| Layer        | Technology                |
|--------------|----------------------------|
| Frontend     | React, TypeScript, Tailwind CSS, Recharts |
| File Parsing | CSV from Wireshark exports |
| Detection    | Rule-based logic, heuristic threshold detection |


---

## ⚙️ How to Run the Project Locally

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/nids.git
cd nids
---
cd project
npm install
npm run dev
---
Upload Wireshark CSV
Open Wireshark and capture traffic.

Go to File → Export Packet Dissections → As CSV.

Upload the .csv via the NIDS Dashboard.
## 📁 Folder Structure

