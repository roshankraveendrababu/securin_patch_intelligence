
# 🛠 Patch Intelligence Information System



Patch Intelligence Information System is a graph-based vulnerability and patch management tool that helps IT security teams:

✔ Identify vulnerabilities (CVEs) 📌

✔ Map affected products (CPEs) 🏭

✔ Find corresponding patches 🛠

✔ Visualize relationships in Neo4j 📊

By leveraging Neo4j, NVD APIs, and automated web scraping, this tool provides real-time insights for securing infrastructure.



## 🚀 Features

✅ Automated CVE & CPE Mapping – Fetch vulnerabilities and affected products.

✅ Graph-Based Patch Management – Store relationships in Neo4j for fast queries.

✅ Web Scraping Backup – If APIs fail, scrape missing CPEs from the NVD website.

✅ Batch Processing & Multi-threading – Handles large datasets efficiently.

✅ Deployment-Ready – Can be hosted on AWS, Azure, or a local server.




## 🛠 Tech Stack 
  

---

**📌 Programming Language**  
- 🐍 **Python 3.8+** – Used for scripting, automation, and data processing.  

---


---

**📂 Database & Data Storage**  
- 🗂️ **Neo4j** – Graph database to store CVEs, CPEs, and patches.  
- 📜 **Cypher Query Language (CQL)** – For querying the Neo4j graph database.  
- 📄 **JSON / XML Files** – Used for storing vulnerability and patch datasets.  


---

---

**🌐 Data Collection & APIs**  
- 🌎 **NVD API** – Fetches CVE and CPE data from the **National Vulnerability Database (NVD)**.  
- 🔍 **Web Scraping (BeautifulSoup)** – Extracts missing CPEs when API fails.  
- 📡 **Requests & HTTP Handling** – Fetches real-time vulnerability and patch information. 

---

---
### **⚡ Performance Optimization**  
- 🔄 **Threading & Batch Processing** – Handles large-scale data efficiently.  
- 🔁 **Retries & Error Handling** – Prevents failures due to API rate limits.  

---

---

### **📦 Libraries & Dependencies**  
| 📦 **Library**  | 📝 **Usage**  |  
|---------------|--------------|  
| `requests` | API requests & web scraping |  
| `beautifulsoup4` | Extracts data from NVD web pages |  
| `neo4j` | Connects and interacts with Neo4j database |  
| `re` | Parses CPE names into structured metadata |  
| `time` | Implements retry delays for API calls |  
| `json` | Reads and writes structured data files |  

---

 

---

### **🔐 Security & Best Practices**  
- 🔑 **Environment Variables & Config Files** – Secures database credentials and API keys.  
- 🚫 **`.gitignore`** – Prevents committing sensitive data to GitHub.  

---




## Deployment

💻 Installation & Setup

🔹 Prerequisites

Before running the project, install the following:

✅ Python 3.8+ – Install from Python.org

✅ Neo4j – Install from Neo4j Download

✅ Pip & Virtual Environment



1. **Clone the repository**



```bash
git clone https://github.com/your-username/Patch-Intelligence-Info-System.git
cd Patch-Intelligence-Info-System
```

2. Install Dependencies
```bash
pip install -r requirements.txt
```

3. Configure Database & API Keys
Edit config/config.json with your Neo4j credentials and NVD API key:
```bash
{
  "neo4j_uri": "bolt://localhost:7687",
  "neo4j_user": "neo4j",
  "neo4j_password": "your_password_here",
  "nvd_api_key": "your_api_key_here"
}
```






## Screenshots

![Final Graph Database](https://github.com/user-attachments/assets/73c2bea3-cc66-4e37-b4aa-30beb3f5ab17)

![patches-->vulnerability](https://github.com/user-attachments/assets/f8c06900-377f-401b-9798-5693f279dac0)

![vulnerabitity-->cpe](https://github.com/user-attachments/assets/67f5ebcf-5b15-4c4c-916f-b3a4fa0c1083)


## 🛠 Running the Project
1️⃣ Import Vulnerabilities (CVEs)
```bash
python scripts/import_vulnerability.py
```

2️⃣ Import CPEs (Affected Products)
```bash
python scripts/import_cpe.py
```

3️⃣ Import Patches
```bash
python scripts/import_patches.py
```





## 🛠 Contributions

Contributions are always welcome!


👨‍💻 How to Contribute

1. Fork the repo 🍴

2. Create a new branch (feature-branch)

3. Commit your changes

4. Submit a pull request


## 🙏 Acknowledgments

We would like to express our gratitude to the following:

1. Neo4j & Cypher Community – For providing a powerful graph database that made this project possible.

2. National Vulnerability Database (NVD) – For offering open access to cybersecurity vulnerability data.

3. Open-Source Contributors & Python Community – For maintaining robust libraries such as requests, BeautifulSoup, and py2neo, which enabled efficient data processing.
4. Cybersecurity Researchers & Analysts

## Authors

- [@Roshan.K.R](https://github.com/roshankraveendrababu)

- [@Ramkumar.B](https://github.com/Rk-Engineer)

## 🔗 Links

[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/roshankr09/)
[![twitter](https://img.shields.io/badge/twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://x.com/RoshanKR0912)


