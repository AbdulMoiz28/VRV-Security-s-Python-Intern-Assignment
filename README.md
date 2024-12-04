# VRV-Security-s-Python-Intern-Assignment

# Log Analysis System

## Overview
A robust Python-based log analysis tool that extracts insights from web server logs, providing traffic analysis and threat detection. It supports multi-format reporting in HTML, CSV, and terminal, assisting with cybersecurity and network performance monitoring.

## 🌟 Features
- **Detailed IP Traffic Analysis**
  - Tracks request frequency for each IP address
  - Provides comprehensive traffic distribution insights

- **Endpoint Usage Monitoring**
  - Identifies most frequently accessed web endpoints
  - Helps understand resource utilization

- **Advanced Security Analysis**
  - Detects suspicious activities based on login attempts
  - Flags potential security threats

- **Flexible Output Formats**
  - Interactive HTML reports
  - Exportable CSV files
  - Detailed terminal output

## 📦 Prerequisites
- Python 3.6+
- `prettytable` library

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/AbdulMoiz28/VRV-Security-s-Python-Intern-Assignment.git
cd log-analysis-system
```

### 2. Install Dependencies
```bash
pip install prettytable
```

## 🔧 Usage

### Running the Analysis
```bash
python log_analysis.py
```

### Output Files
- `log_analysis_report.html`: Interactive HTML report
- `log_analysis_results.csv`: Raw data export
- Terminal: Immediate analysis results

## 📊 Report Components
1. **Summary Statistics**
   - Total requests
   - Unique IP addresses
   - Bandwidth usage
   - Time range of logs

2. **IP Address Activity**
   - Detailed breakdown of requests per IP

3. **Endpoint Analysis**
   - Most accessed URLs/endpoints

4. **Security Alerts**
   - Detection of suspicious login activities

## 🔍 Customization
Modify `log_analysis.py` to:
- Change failed login threshold
- Adjust output file paths
- Customize analysis parameters

## 📝 Sample Log Format
Supports standard Apache/Nginx log formats
- Sample log file (`sample.log`) included for testing

## 🖼️ Sample Output
![Log Analysis Report]
<img width="1680" alt="image" src="log_analysis_report-1.png">

## 🛡️ Security Notes
- Flags IPs with multiple failed login attempts
- Provides threshold-based suspicious activity detection

## 💡 Requirements
- Python Libraries:
  - `re`
  - `csv`
  - `collections`
  - `datetime`
  - `typing`
  - `prettytable`
```
