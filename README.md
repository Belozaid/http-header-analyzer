🔐 HTTP Header Analyzer 
# 🔐 HTTP Header Analyzer

[![GitHub stars](https://img.shields.io/github/stars/Belozaid/http-header-analyzer)](https://github.com/Belozaid/http-header-analyzer/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/BelozaidE/http-header-analyzer)](https://github.com/Belozaid/http-header-analyzer/issues)
Advanced Tool for HTTP Header Security Analysis and Hidden Route Discovery

📖 About the Project
This tool is a comprehensive security scanner script built in Python. It aims to help penetration testers and website administrators examine the security settings in HTTP headers and search for sensitive routing files, while delivering high performance thanks to its parallel processing capabilities.

✨ Key Features
- 🚀 Parallel analysis (Multi-threading) : Scanning dozens of sites in seconds using a synchronized threading system.
- 🔍 Security Header Check: A thorough analysis of CSP, HSTS, X-Frame-Options with an explanation of each missing vulnerability.
- 🤖 Exploring robots.txt: Automated scanning of routing files to extract sensitive and hidden paths from search engines.
- 📊 Smart Reports: Export results in a structured JSON format for easy integration with other tools.
- 🛠️ Advanced error handling: An intelligent system for handling disconnections, timeouts, and invalid links.

🛠️ Installation and Operation
Prerequisites
Python 3.8 or later.

A requests library for handling HTTP protocol.

1. Download the project
   git clone https://github.com/Belozaid/http-header-analyzer.git
   cd http-header-analyzer

2. Install the required libraries
   pip install requirements.txt
   
4. Run the tool
# Analysis of one site
python analyzer.py -u google.com

#Analysis of a Saudi government website
python analyzer.py -u moe.gov.sa

# Creating an Arabic URL file (for the first time)
python analyzer.py --create-arabic

# Site List Analysis
python analyzer.py -f urls_arabic.txt

# Creating an Arabic HTML report
python analyzer.py -f urls_arabic.txt --arabic-report -o تقرير_الأمان

# Parallel analysis with 10 threads
python analyzer.py -f urls.txt --threads 10 -o  تحليل_سريع

📊 Example of results

============================================================
🔍 Analyzing: moe.gov.sa
============================================================

🌐 DNS Availability Check:
  ✅ DNS resolved: 91.195.88.235
📝 Added HTTPS: https://moe.gov.sa

✅ Final URL: https://moe.gov.sa/ar/pages/default.aspx
📊 Status Code: 200

📋 Security Headers Analysis:
  ✅ Strict-Transport-Security: max-age=31536000; includeSubDomains
     📝 Protects against SSL Strip attacks
  ❌ X-Frame-Options
     ⚠️ Missing: Prevents Clickjacking
  ✅ X-Content-Type-Options: nosniff
     📝 Prevents MIME sniffing
  ✅ Content-Security-Policy: frame-ancestors 'self' teams.microsoft.com
     📝 Prevents XSS and injection attacks

🍪 Cookie Security Analysis:
  🔴 APPLICATION_POOL=!ntg5v6zyZXUbHmj77osIVpSF0rftK... [HIGH RISK]

🔒 SSL Certificate Analysis:
  • Issuer: DigiCert Inc
  • Subject: *.moe.gov.sa
  • Expires: May 28 23:59:59 2026 GMT
  • Days left: 71 ✅

📈 Overall Risk Score: 15/100
  🟢 LOW RISK - Good security posture
