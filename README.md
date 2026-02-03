<div align="center">

# Cyber Clinic Web Application 

### *CS 426 Senior Project*
**Spring 2026 •University of Nevada,Reno• Department of Computer Science & Engineering**

[![University](https://img.shields.io/badge/University-Nevada%2C%20Reno-blue.svg)](https://www.unr.edu/)
[![Course](https://img.shields.io/badge/Course-CS%20425-green.svg)](https://catalog.unr.edu/preview_course_nopop.php?catoid=58&coid=1093494&print)
[![Status](https://img.shields.io/badge/Status-In%20Development-orange.svg)](#)
[![Team](https://img.shields.io/badge/Team-13-purple.svg)](#)


</div>

---
## Team Information 

**Team Number:** 13
**Team Name:** Cyberr Clinc 
**Team Members:**
- *(Leslie Becerra Austin Finch,Vanessa Medina, Manuel Morales-Marroquin)*

---
## Intructors & Exteral Advisors 

**Instructors:**
-Dave Feil-Seifer, Vinh Le, Stosh Peterson, & Richie White  - Computer Science & Engineering, University of Nevada, Reno 

**External Advisors:**
- * Dr. Bill Doherty & Dr. Shamik Sengupta* - Cybersecuirty Center, University of Nevada, Reno
---
## Project Title
**Cyber Clinic Web Application: Accessible Cybersecurity for small organizations** This website documents our **CS 426 Senior Prokject in Computer Science (Spring 2026)** at the **Inoversity of Nevada,Reno - Deparment of Computer Science & Engineering**

---
## Project Description

Small organization such as lcal businesses, tribal agencies, and community nonprofits often lack the budget and technical expertise needed to preform regular cybersecuirty assessments. Commercual vulnerability scanners can cost hundreds r even thosands of dollars annually, crreatinf a barrier that leaves many organizations exposed to preventable risks. The *Cyber Web Application** is designed as an afforadable and easy to us alternative that helps non technical users understand their cybersecuirty posture.The system integrates trusted open source tools such as **Nmap** and **Nikto to preform vulerablity scans onpublic facing systems. Instead of presenting raw technical output, the platform translates scan results into **plain-language rports** with clear explanations and suggested remediation steps.The long-term goal of this project is to demonstrate how **automation, usability, and education ** can work together to make cybersecuirt more accessible.By lowering financial and techinal barrier, the Cyber Clinic Web Application aims to empower small organization to make proactive steps towars improving their secuirty. 

---

## Project Vision

Team 13 is proposing the Cyber Clinic Web Application, an affordable and simple alternative to commercial vulnerability scanners that can cost more than $1,000. The project supports the mission of the Cyber Clinic, a student-led nonprofit founded at the University of Nevada, Las Vegas (UNLV), which is now opening a chapter at the University of Nevada, Reno (UNR) to help small businesses, tribal agencies, and local governments address cybersecurity risks. Our prototype includes functional user authentication, a working dashboard, and integrated scanning for public domains/IPs using open-source tools such as Nmap and Nikto. The system produces readable reports that translates technical scanner output into plain English with clear suggested fixes, giving non-technical users a clear first assessment and a direct path to contact Cyber Clinic for further remediation and education. 

---
### **Planned User Journey**

1. **Register** → Users create secure accounts
2. **Submit** → Enter domain/IP for assessment  
3. **Download** → Get lightweight local scanner for any subnet(s) you wish to scan
4. **Scan** → Execute Nmap/Nikto on domain and/or subnet(s)
5. **Report** → Receive actionable security insights
6. **Connect** → Contact the Cyber Clinic for expert guidance

> **Note:** This project is currently in early development as part of our CS 425 Software Engineering course.

---

## Planned Technology Stack

| Component | Technology | Status |
|-----------|------------|--------|
| **Frontend** | HTML5, CSS3, JavaScript | 📋 Planned |
| **Backend** | Python, Flask/FastAPI | 📋 Planned |
| **Database** | PostgreSQL, SQLAlchemy | 📋 Planned |
| **Security Tools** | Nmap, Nikto, OpenVAS | 📋 Planned |
| **Reporting** | SysReptor | 📋 Planned |
| **AI Analysis** | Ollama | 📋 Planned |

### **What We're Building**

Our application will provide:
- **💰 Affordable scanning** - Free alternative to expensive commercial tools
- **🔒 Secure architecture** - Local scanning to protect sensitive data  
- **📝 Clear reporting** - Plain-English vulnerability summaries
- **📞 Expert support** - Direct connection to cybersecurity analysts
- **🏢 Small org focus** - Built specifically for resource constrained organizations



---

## Getting Started (For Development)

### Prerequisites
- 📦 Docker
- 🐍 Python 3.10+
- 🔧 Git
- 🌐 Modern browser (Chrome, Edge, Firefox)

### Current Setup

```bash
#Clone the repository
git clone https://github.com/VanessaMedinaUNR/CyberClinic.git
cd CyberClinic

#Start Web App and all associated containers
cd Web
cp .env.dev .env
#Update .env file with secrets

cd reptor/sysreptor/deploy
cp app.env.example app.env
#Update app.env as shown at https://docs.sysreptor.com/setup/installation/#manual-installation

docker-compose up

#Create virtual environment for downloadable application testing
cd.. # back into ~/CyberClinic/
cd Application
python3 -m venv .venv
source .venv/bin/activate #On Windows: .venv\Scripts\activate

pip install -r requirements.txt
cd src
python -m  PyInstaller --distpath /dist/{Your Distribution} -n CyberClinic --noconfirm client_application.py
```

> **Development Note:** Full installation instructions will be updated as we build out the application components.

---

## Project Documentation

### Academic Context
- **Course:** CS 425 - Software Engineering
- **Institution:** University of Nevada, Reno
- **Semester:** Fall 2025
- **Team:** #13

### Supporting Documents
- [x Proposal](docs/x.md) *(Coming Soon)*
- [y Requirements](docs/y.md) *(Coming Soon)*
- [z Design](docs/z.md) *(Coming Soon)*

---

## 👥 Team Members

<div align="center">

<table>
<tr>
<td align="center">
<a href="#"><img src="https://github.com/github.png" width="100px;" alt="Leslie Becerra"/></a><br />
<sub><b>Leslie Becerra</b></sub><br/>
<sub><em>x Developer/Engineer</em></sub><br/>
<sub>Focus: x, y, z</sub>
</td>
<td align="center">
<a href="#"><img src="https://github.com/Austin-Finch.png" width="100px;" alt="Austin Finch"/></a><br />
<sub><b>Austin Finch</b></sub><br/>
<sub><em>x Developer/Engineer</em></sub><br/>
<sub>Focus: Dockerization, Database, Backend</sub>
</td>
<td align="center">
<a href="https://github.com/VanessaMedinaUNR"><img src="https://github.com/VanessaMedinaUNR.png" width="100px;" alt="Vanessa Medina"/></a><br />
<sub><b>Vanessa Medina</b></sub><br/>
<sub><em>x Developer/Engineer</em></sub><br/>
<sub>Focus: Frontend, Backend to Frontend Integration</sub>
</td>
<td align="center">
<a href="https://github.com/Wovern-NV"><img src="https://github.com/Wovern-NV.png" width="100px;" alt="Manuel Morales-Marroquin"/></a><br />
<sub><b>Manuel Morales-Marroquin</b></sub><br/>
<sub><em>x Developer/Engineer</em></sub><br/>
<sub>Focus: x, y, z</sub>
</td>
</tr>
</table>

</div>

### 🎓 **Academic Support**
- **Instructors:** Dr. Dave Feil-Seifer, Vinh Le, Stosh Peterson, Richie White
- **External Advisors:** Dr. Bill Doherty, Dr. Shamik Sengupta

---

<div align="center">

### 🛡️ **Building the Future of Accessible Cybersecurity** 🛡️

*A CS 425 Software Engineering Project*

**University of Nevada, Reno • Computer Science & Engineering**

---

**📅 Project Timeline:** Fall 2025 | **👥 Team 13** | **🚧 In Development**

</div>
