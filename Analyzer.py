import requests
import argparse
import json
import csv
import re
from urllib.parse import urlparse
from datetime import datetime
import concurrent.futures
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import ssl
import socket
import os
import dns.resolver
import subprocess
import sys
from typing import List, Dict, Set
import time

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SubdomainEnumerator:
    """Class for enumerating subdomains using multiple tools"""
    
    def __init__(self):
        self.subdomains = set()
        self.tools_available = self.check_tools()
        
    def check_tools(self) -> Dict[str, bool]:
        """Check availability of installed tools"""
        tools = {
            'subfinder': False,
            'amass': False,
            'assetfinder': False
        }
        
        # Check for subfinder
        try:
            result = subprocess.run(['subfinder', '-h'], capture_output=True, text=True)
            tools['subfinder'] = result.returncode == 0
        except FileNotFoundError:
            pass
            
        # Check for amass
        try:
            result = subprocess.run(['amass', '-h'], capture_output=True, text=True)
            tools['amass'] = result.returncode == 0
        except FileNotFoundError:
            pass
            
        # Check for assetfinder
        try:
            result = subprocess.run(['assetfinder', '-h'], capture_output=True, text=True)
            tools['assetfinder'] = result.returncode == 0
        except FileNotFoundError:
            pass
            
        return tools
    
    def install_tools_guide(self):
        """Provide installation guide for missing tools"""
        print("\n📦 Installation Guide for Missing Tools:")
        print("="*50)
        
        if not self.tools_available['subfinder']:
            print("\n🔧 Installing Subfinder:")
            print("  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            print("  or: sudo apt install subfinder")
            
        if not self.tools_available['amass']:
            print("\n🔧 Installing Amass:")
            print("  go install -v github.com/OWASP/Amass/v3/...@master")
            print("  or: sudo apt install amass")
            
        if not self.tools_available['assetfinder']:
            print("\n🔧 Installing Assetfinder:")
            print("  go install github.com/tomnomnom/assetfinder@latest")
            
        print("\n💡 Note: Make sure Go is installed first:")
        print("  sudo apt install golang-go")
        print("  or visit: https://golang.org/dl/")
    
    def run_subfinder(self, domain: str) -> Set[str]:
        """Run Subfinder to collect subdomains"""
        subdomains = set()
        if not self.tools_available['subfinder']:
            print("  ⚠️ Subfinder not installed - skipping...")
            return subdomains
            
        try:
            print(f"  🔍 Running Subfinder on {domain}...")
            cmd = ['subfinder', '-d', domain, '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip():
                        subdomains.add(line.strip())
                print(f"  ✅ Subfinder found {len(subdomains)} subdomains")
            else:
                print(f"  ⚠️ Subfinder error: {result.stderr[:100]}")
                
        except subprocess.TimeoutExpired:
            print("  ⚠️ Subfinder timeout exceeded")
        except Exception as e:
            print(f"  ⚠️ Error running Subfinder: {e}")
            
        return subdomains
    
    def run_amass(self, domain: str) -> Set[str]:
        """Run Amass to collect subdomains"""
        subdomains = set()
        if not self.tools_available['amass']:
            print("  ⚠️ Amass not installed - skipping...")
            return subdomains
            
        try:
            print(f"  🔍 Running Amass on {domain} (may take time)...")
            cmd = ['amass', 'enum', '-passive', '-d', domain, '-o', '/dev/stdout']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith('#'):
                        subdomains.add(line.strip())
                print(f"  ✅ Amass found {len(subdomains)} subdomains")
            else:
                print(f"  ⚠️ Amass error: {result.stderr[:100]}")
                
        except subprocess.TimeoutExpired:
            print("  ⚠️ Amass timeout exceeded")
        except Exception as e:
            print(f"  ⚠️ Error running Amass: {e}")
            
        return subdomains
    
    def run_assetfinder(self, domain: str) -> Set[str]:
        """Run Assetfinder to collect subdomains"""
        subdomains = set()
        if not self.tools_available['assetfinder']:
            print("  ⚠️ Assetfinder not installed - skipping...")
            return subdomains
            
        try:
            print(f"  🔍 Running Assetfinder on {domain}...")
            cmd = ['assetfinder', '-subs-only', domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip():
                        subdomains.add(line.strip())
                print(f"  ✅ Assetfinder found {len(subdomains)} subdomains")
            else:
                print(f"  ⚠️ Assetfinder error: {result.stderr[:100]}")
                
        except subprocess.TimeoutExpired:
            print("  ⚠️ Assetfinder timeout exceeded")
        except Exception as e:
            print(f"  ⚠️ Error running Assetfinder: {e}")
            
        return subdomains
    
    def enumerate(self, domain: str, use_all: bool = True) -> Set[str]:
        """Run all available tools for subdomain enumeration"""
        print(f"\n🌐 Starting subdomain enumeration for: {domain}")
        print("="*50)
        
        all_subdomains = set()
        
        # Run tools in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            
            if use_all or self.tools_available['subfinder']:
                futures.append(executor.submit(self.run_subfinder, domain))
            if use_all or self.tools_available['amass']:
                futures.append(executor.submit(self.run_amass, domain))
            if use_all or self.tools_available['assetfinder']:
                futures.append(executor.submit(self.run_assetfinder, domain))
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                all_subdomains.update(future.result())
        
        # Add main domain
        all_subdomains.add(domain)
        
        print(f"\n📊 Total unique subdomains: {len(all_subdomains)}")
        
        # Save results
        self.subdomains = all_subdomains
        return all_subdomains
    
    def save_subdomains(self, filename: str):
        """Save subdomains to file"""
        if not self.subdomains:
            print("No subdomains to save")
            return
            
        os.makedirs('subdomains', exist_ok=True)
        filepath = f"subdomains/{filename}"
        
        with open(f"{filepath}.txt", 'w', encoding='utf-8') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        print(f"✅ Saved {len(self.subdomains)} subdomains to {filepath}.txt")
        
        # Save as JSON as well
        with open(f"{filepath}.json", 'w', encoding='utf-8') as f:
            json.dump({
                'domain': filename.replace('_subdomains', ''),
                'count': len(self.subdomains),
                'subdomains': sorted(list(self.subdomains)),
                'timestamp': datetime.now().isoformat()
            }, f, ensure_ascii=False, indent=2)
        
        print(f"✅ Saved JSON to {filepath}.json")

class HTTPHeaderAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.results = []
        self.subdomain_enum = SubdomainEnumerator()
        self.statistics = {
            'total': 0,
            'hsts': 0,
            'xframe': 0,
            'csp': 0,
            'secure_cookies': 0,
            'ssl_valid': 0,
            'ssl_expiring_soon': 0,
            'subdomains_found': 0
        }
        
    def enhanced_dns_check(self, hostname):
        """Advanced DNS check"""
        try:
            answers = dns.resolver.resolve(hostname, 'A')
            ips = [str(r) for r in answers]
            return True, ips
        except dns.resolver.NXDOMAIN:
            return False, ["Domain does not exist"]
        except dns.resolver.NoAnswer:
            return False, ["No A record found"]
        except dns.resolver.Timeout:
            return False, ["DNS timeout"]
        except Exception as e:
            return False, [str(e)]

    def check_website_availability(self, url):
        """Multi-method availability check"""
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        
        if not hostname:
            hostname = url.replace('http://', '').replace('https://', '').split('/')[0]
        
        print(f"  🔍 Checking availability for: {hostname}")
        
        # Try DNS first
        dns_ok, dns_info = self.enhanced_dns_check(hostname)
        if not dns_ok:
            print(f"  ⚠️ DNS Warning: {hostname} - {dns_info[0]}")
            
            # Try simple ping
            try:
                ip = socket.gethostbyname(hostname)
                print(f"  ✅ Resolved via socket: {ip}")
                return True, f"Resolved via socket: {ip}"
            except socket.gaierror:
                print(f"  ❌ DNS resolution failed completely for {hostname}")
                return False, "DNS resolution failed"
        else:
            print(f"  ✅ DNS resolved: {', '.join(dns_info[:3])}")
            return True, f"DNS successful: {', '.join(dns_info[:3])}"
    
    def enumerate_subdomains(self, domain: str, use_all_tools: bool = True):
        """Enumerate subdomains for the given domain"""
        print(f"\n🔍 Starting subdomain enumeration for: {domain}")
        
        # Check tool availability
        if not any(self.subdomain_enum.tools_available.values()):
            print("⚠️ No tools found installed!")
            self.subdomain_enum.install_tools_guide()
            
            response = input("\nDo you want to continue without subdomain enumeration? (y/n): ")
            if response.lower() != 'y':
                return set()
        
        # Enumerate subdomains
        subdomains = self.subdomain_enum.enumerate(domain, use_all_tools)
        
        # Update statistics
        self.statistics['subdomains_found'] += len(subdomains)
        
        return subdomains
    
    def analyze_multiple_subdomains(self, domain: str, max_sites: int = 50):
        """Analyze multiple subdomains"""
        # Enumerate subdomains first
        subdomains = self.enumerate_subdomains(domain)
        
        if not subdomains:
            print("❌ No subdomains found")
            return []
        
        print(f"\n🔐 Starting security analysis of {min(len(subdomains), max_sites)} subdomains...")
        
        # Convert subdomains to URLs
        urls = []
        for sub in list(subdomains)[:max_sites]:
            urls.append(f"https://{sub}")
            urls.append(f"http://{sub}")
        
        # Analyze subdomains in parallel
        analyzed_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.analyze_url, url): url for url in urls}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    analyzed_results.append(result)
        
        # Save discovered subdomains
        self.subdomain_enum.save_subdomains(f"{domain}_subdomains")
        
        return analyzed_results

    def analyze_security_headers(self, headers):
        """Analyze security headers and evaluate them"""
        security_analysis = {
            'Strict-Transport-Security': {'present': False, 'value': None, 'status': '❌', 'severity': 'HIGH', 'note': 'Protects against SSL Strip attacks'},
            'X-Frame-Options': {'present': False, 'value': None, 'status': '❌', 'severity': 'MEDIUM', 'note': 'Prevents Clickjacking'},
            'X-Content-Type-Options': {'present': False, 'value': None, 'status': '❌', 'severity': 'MEDIUM', 'note': 'Prevents MIME sniffing'},
            'Content-Security-Policy': {'present': False, 'value': None, 'status': '❌', 'severity': 'HIGH', 'note': 'Prevents XSS and other attacks'},
            'X-XSS-Protection': {'present': False, 'value': None, 'status': '❌', 'severity': 'LOW', 'note': 'XSS protection for older browsers'},
            'Referrer-Policy': {'present': False, 'value': None, 'status': '❌', 'severity': 'LOW', 'note': 'Controls referrer information'},
            'Permissions-Policy': {'present': False, 'value': None, 'status': '❌', 'severity': 'LOW', 'note': 'Controls browser permissions'}
        }
        
        for header in headers:
            if header in security_analysis:
                security_analysis[header]['present'] = True
                security_analysis[header]['value'] = headers[header]
                security_analysis[header]['status'] = '✅'
                
                # Update statistics
                if header == 'Strict-Transport-Security':
                    self.statistics['hsts'] += 1
                elif header == 'X-Frame-Options':
                    self.statistics['xframe'] += 1
                elif header == 'Content-Security-Policy':
                    self.statistics['csp'] += 1
                
        return security_analysis

    def analyze_cookie_security(self, cookies):
        """Deep analysis of cookie security"""
        if not cookies:
            return []
            
        cookie_list = cookies.split(', ')
        analysis = []
        
        for cookie in cookie_list:
            secure = 'Secure' in cookie
            httponly = 'HttpOnly' in cookie
            samesite = 'SameSite=' in cookie
            
            # Check for SameSite value
            samesite_value = 'None'
            if samesite:
                match = re.search(r'SameSite=([^;]+)', cookie)
                if match:
                    samesite_value = match.group(1)
            
            # Determine risk level
            risk = 'HIGH'
            if secure and httponly and samesite_value in ['Strict', 'Lax']:
                risk = 'LOW'
            elif secure and (httponly or samesite):
                risk = 'MEDIUM'
            
            analysis.append({
                'cookie': cookie[:60] + '...' if len(cookie) > 60 else cookie,
                'secure': '✅' if secure else '❌',
                'httponly': '✅' if httponly else '❌',
                'samesite': '✅' if samesite else '❌',
                'samesite_value': samesite_value,
                'risk': risk
            })
            
            if secure and httponly and samesite:
                self.statistics['secure_cookies'] += 1
                
        return analysis

    def check_ssl_certificate(self, hostname, port=443):
        """Check SSL certificate validity and details"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    not_after = cert['notAfter']
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_date - datetime.now()).days
                    
                    # Update statistics
                    if days_remaining > 0:
                        self.statistics['ssl_valid'] += 1
                    if days_remaining < 30 and days_remaining > 0:
                        self.statistics['ssl_expiring_soon'] += 1
                    
                    return {
                        'issuer': issuer.get('organizationName', 'Unknown'),
                        'subject': subject.get('commonName', hostname),
                        'expiry_date': not_after,
                        'days_remaining': days_remaining,
                        'valid': days_remaining > 0,
                        'status': '✅' if days_remaining > 30 else '⚠️' if days_remaining > 0 else '❌'
                    }
        except Exception as e:
            return {'error': str(e), 'status': '❌'}

    def analyze_url(self, url):
        """Comprehensive URL analysis"""
        self.statistics['total'] += 1
        
        print(f"\n{'='*60}")
        print(f"🔍 Analyzing: {url}")
        print(f"{'='*60}")
        
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'security_headers': {},
            'server_info': {},
            'ssl_info': {},
            'redirects': [],
            'response_info': {},
            'dns_info': {},
            'risk_score': 0
        }
        
        try:
            # Extract hostname for DNS check
            hostname = url
            if '://' in url:
                hostname = urlparse(url).netloc
            else:
                hostname = url.split('/')[0]
            
            # DNS Availability Check
            print("\n🌐 DNS Availability Check:")
            dns_available, dns_message = self.check_website_availability(url)
            result['dns_info'] = {
                'available': dns_available,
                'message': dns_message
            }
            
            if not dns_available:
                print(f"  ❌ Website unavailable - stopping analysis")
                return None
            
            # Ensure protocol
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                print(f"📝 Added HTTPS: {url}")
            
            # Make request
            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            
            print(f"\n✅ Final URL: {response.url}")
            print(f"📊 Status Code: {response.status_code}")
            
            # Analyze headers
            print("\n📋 Security Headers Analysis:")
            security_headers = self.analyze_security_headers(response.headers)
            
            risk_score = 0
            for header, info in security_headers.items():
                status = info['status']
                severity = info['severity']
                value = f": {info['value'][:50]}" if info['value'] and info['present'] else ""
                
                # Calculate risk score
                if not info['present']:
                    if severity == 'HIGH':
                        risk_score += 10
                    elif severity == 'MEDIUM':
                        risk_score += 5
                    elif severity == 'LOW':
                        risk_score += 2
                
                print(f"  {status} {header}{value}")
                if info['present'] and info['note']:
                    print(f"     📝 {info['note']}")
                elif not info['present']:
                    print(f"     ⚠️ Missing: {info['note']}")
            
            result['security_headers'] = security_headers
            
            # Server info
            if 'Server' in response.headers:
                print(f"\n🖥️ Server: {response.headers['Server']}")
                result['server_info']['server'] = response.headers['Server']
            
            # Cookie analysis
            if 'Set-Cookie' in response.headers:
                print("\n🍪 Cookie Security Analysis:")
                cookie_analysis = self.analyze_cookie_security(response.headers['Set-Cookie'])
                for cookie in cookie_analysis:
                    risk_icon = '🔴' if cookie['risk'] == 'HIGH' else '🟡' if cookie['risk'] == 'MEDIUM' else '🟢'
                    print(f"  {risk_icon} {cookie['cookie']}")
                    print(f"     Secure: {cookie['secure']}, HttpOnly: {cookie['httponly']}, SameSite: {cookie['samesite_value']} [{cookie['risk']} Risk]")
                    
                    if cookie['risk'] == 'HIGH':
                        risk_score += 3
                
                result['server_info']['cookie_analysis'] = cookie_analysis
            
            # SSL analysis
            if response.url.startswith('https://'):
                print("\n🔒 SSL Certificate Analysis:")
                hostname = urlparse(response.url).netloc
                ssl_info = self.check_ssl_certificate(hostname)
                
                if 'error' in ssl_info:
                    print(f"  ❌ Error: {ssl_info['error']}")
                    risk_score += 15
                else:
                    print(f"  • Issuer: {ssl_info['issuer']}")
                    print(f"  • Subject: {ssl_info['subject']}")
                    print(f"  • Expires: {ssl_info['expiry_date']}")
                    print(f"  • Days Remaining: {ssl_info['days_remaining']} {ssl_info['status']}")
                    
                    if ssl_info['days_remaining'] < 7:
                        risk_score += 10
                        print("     ⚠️ Critical: Certificate expires soon!")
                    elif ssl_info['days_remaining'] < 30:
                        risk_score += 5
                        print("     ⚠️ Warning: Certificate expires within 30 days")
                
                result['ssl_info'] = ssl_info
            
            # Response info
            print(f"\n📊 Response Details:")
            print(f"  • Content Type: {response.headers.get('Content-Type', 'Not specified')}")
            print(f"  • Size: {len(response.content):,} bytes")
            print(f"  • Time: {response.elapsed.total_seconds():.2f} seconds")
            
            # Overall risk assessment
            print(f"\n📈 Risk Assessment: {risk_score}/100")
            if risk_score < 20:
                print("  🟢 Low Risk - Good security posture")
            elif risk_score < 50:
                print("  🟡 Medium Risk - Security improvements needed")
            else:
                print("  🔴 High Risk - Urgent security fixes required")
            
            result['risk_score'] = risk_score
            result['response_info'] = {
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type'),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds()
            }
            
            self.results.append(result)
            return result
            
        except requests.exceptions.SSLError as e:
            print(f"❌ SSL Error: {e}")
            print("  💡 Try analysis without SSL or verify certificate manually")
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Connection Error: {e}")
            print("  💡 Check internet connection or if the website is working")
            return None
        except requests.exceptions.Timeout as e:
            print(f"❌ Timeout Error: {e}")
            print("  💡 Website is taking too long to respond")
            return None
        except Exception as e:
            print(f"❌ Unexpected Error: {e}")
            return None

    def save_results(self, filename, format='json'):
        """Save analysis results"""
        if not self.results:
            print("No results to save")
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        filepath = f"results/{filename}"
        
        if format == 'json':
            with open(f"{filepath}.json", 'w', encoding='utf-8') as f:
                json.dump({
                    'statistics': self.statistics,
                    'results': self.results
                }, f, ensure_ascii=False, indent=2)
            print(f"✅ Results saved to {filepath}.json")
            
        elif format == 'csv':
            with open(f"{filepath}.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Status', 'DNS', 'HSTS', 'X-Frame-Options', 'CSP', 'SSL', 'SSL Days', 'Risk Score'])
                
                for r in self.results:
                    security = r.get('security_headers', {})
                    ssl = r.get('ssl_info', {})
                    dns = r.get('dns_info', {})
                    writer.writerow([
                        r['url'],
                        r.get('response_info', {}).get('status_code', 'N/A'),
                        '✅' if dns.get('available') else '❌',
                        '✅' if security.get('Strict-Transport-Security', {}).get('present') else '❌',
                        '✅' if security.get('X-Frame-Options', {}).get('present') else '❌',
                        '✅' if security.get('Content-Security-Policy', {}).get('present') else '❌',
                        ssl.get('status', 'N/A'),
                        ssl.get('days_remaining', 'N/A'),
                        r.get('risk_score', 'N/A')
                    ])
            print(f"✅ Results saved to {filepath}.csv")

    def generate_arabic_report(self, filename):
        """Generate Arabic HTML report"""
        if not self.results:
            print("No results to generate report")
            return
        
        # Create reports directory
        os.makedirs('reports', exist_ok=True)
        
        html = f"""
        <!DOCTYPE html>
        <html dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>📊 Website Security Report</title>
            <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
            <style>
                body {{
                    font-family: 'Cairo', 'Arial', sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    margin: 0;
                    padding: 20px;
                    min-height: 100vh;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                }}
                .header {{
                    background: white;
                    padding: 30px;
                    border-radius: 20px;
                    text-align: center;
                    margin-bottom: 30px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }}
                .header h1 {{
                    margin: 0;
                    color: #333;
                    font-size: 2.5em;
                }}
                .header p {{
                    color: #666;
                    font-size: 1.2em;
                    margin: 10px 0 0;
                }}
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .card {{
                    background: white;
                    padding: 25px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    text-align: center;
                    transition: transform 0.3s;
                }}
                .card:hover {{
                    transform: translateY(-5px);
                }}
                .card h3 {{
                    margin: 0 0 15px;
                    color: #333;
                    font-size: 1.3em;
                }}
                .card .number {{
                    font-size: 2.5em;
                    font-weight: bold;
                }}
                .good {{ color: #4caf50; }}
                .warning {{ color: #ff9800; }}
                .danger {{ color: #f44336; }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-bottom: 30px;
                }}
                .stat-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 10px;
                    text-align: center;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }}
                .table-container {{
                    background: white;
                    border-radius: 15px;
                    padding: 20px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    overflow-x: auto;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    font-family: 'Cairo', sans-serif;
                }}
                th {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 15px;
                    font-weight: 600;
                    font-size: 1em;
                }}
                td {{
                    padding: 12px;
                    text-align: center;
                    border-bottom: 1px solid #ddd;
                }}
                tr:hover {{
                    background-color: #f8f9fa;
                }}
                .risk-badge {{
                    padding: 5px 15px;
                    border-radius: 25px;
                    font-weight: bold;
                    display: inline-block;
                    font-size: 0.9em;
                }}
                .low {{ background: #c8e6c9; color: #2e7d32; }}
                .medium {{ background: #fff3e0; color: #ef6c00; }}
                .high {{ background: #ffebee; color: #c62828; }}
                .status-icon {{
                    font-size: 1.2em;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    color: white;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Website Security Analysis Report</h1>
                    <p>Report Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <p>Total Websites Analyzed: {len(self.results)}</p>
                    <p>Subdomains Discovered: {self.statistics['subdomains_found']}</p>
                </div>

                <div class="summary">
                    <div class="card">
                        <h3>🟢 Secure</h3>
                        <div class="number good">{sum(1 for r in self.results if r.get('risk_score', 100) < 20)}</div>
                        <p>Websites</p>
                    </div>
                    <div class="card">
                        <h3>🟡 Medium</h3>
                        <div class="number warning">{sum(1 for r in self.results if 20 <= r.get('risk_score', 0) < 50)}</div>
                        <p>Websites</p>
                    </div>
                    <div class="card">
                        <h3>🔴 Critical</h3>
                        <div class="number danger">{sum(1 for r in self.results if r.get('risk_score', 0) >= 50)}</div>
                        <p>Websites</p>
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="stat-item">
                        <div>🔒 HSTS</div>
                        <div class="number good">{self.statistics['hsts']}</div>
                    </div>
                    <div class="stat-item">
                        <div>🛡️ X-Frame-Options</div>
                        <div class="number good">{self.statistics['xframe']}</div>
                    </div>
                    <div class="stat-item">
                        <div>📝 CSP</div>
                        <div class="number good">{self.statistics['csp']}</div>
                    </div>
                    <div class="stat-item">
                        <div>🍪 Secure Cookies</div>
                        <div class="number good">{self.statistics['secure_cookies']}</div>
                    </div>
                    <div class="stat-item">
                        <div>✅ Valid SSL</div>
                        <div class="number good">{self.statistics['ssl_valid']}</div>
                    </div>
                    <div class="stat-item">
                        <div>⚠️ SSL Expiring Soon</div>
                        <div class="number warning">{self.statistics['ssl_expiring_soon']}</div>
                    </div>
                    <div class="stat-item">
                        <div>🌐 Subdomains</div>
                        <div class="number good">{self.statistics['subdomains_found']}</div>
                    </div>
                </div>

                <div class="table-container">
                    <table>
                        <tr>
                            <th>Website</th>
                            <th>DNS</th>
                            <th>SSL</th>
                            <th>Days Left</th>
                            <th>HSTS</th>
                            <th>X-Frame</th>
                            <th>CSP</th>
                            <th>Risk Score</th>
                            <th>Assessment</th>
                        </tr>
        """
        
        for result in self.results:
            risk = result.get('risk_score', 0)
            if risk < 20:
                risk_class = "low"
                risk_text = "🟢 Secure"
            elif risk < 50:
                risk_class = "medium"
                risk_text = "🟡 Medium"
            else:
                risk_class = "high"
                risk_text = "🔴 Critical"
            
            ssl = result.get('ssl_info', {})
            ssl_days = ssl.get('days_remaining', 'N/A')
            ssl_status = ssl.get('status', '❌')
            
            dns = result.get('dns_info', {})
            dns_status = '✅' if dns.get('available') else '❌'
            
            security = result.get('security_headers', {})
            
            html += f"""
                        <tr>
                            <td><strong>{result['url']}</strong></td>
                            <td class="status-icon">{dns_status}</td>
                            <td class="status-icon">{ssl_status}</td>
                            <td>{ssl_days}</td>
                            <td class="status-icon">{'✅' if security.get('Strict-Transport-Security', {}).get('present') else '❌'}</td>
                            <td class="status-icon">{'✅' if security.get('X-Frame-Options', {}).get('present') else '❌'}</td>
                            <td class="status-icon">{'✅' if security.get('Content-Security-Policy', {}).get('present') else '❌'}</td>
                            <td>{risk}/100</td>
                            <td><span class="risk-badge {risk_class}">{risk_text}</span></td>
                        </tr>
            """
        
        html += """
                    </table>
                </div>
                
                <div class="footer">
                    <p>Generated by HTTP Header Analyzer © 2026</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(f"reports/{filename}.html", 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"✅ Report saved to reports/{filename}.html")

def create_sample_urls_file():
    """Create a sample urls.txt file"""
    sample_urls = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "example.com",
        "bing.com",
        "wikipedia.org",
        "reddit.com"
    ]
    
    with open('urls.txt', 'w') as f:
        for url in sample_urls:
            f.write(url + '\n')
    
    print("✅ Created urls.txt with 7 URLs")

def create_arabic_urls_file():
    """Create Arabic URLs file"""
    arabic_urls = [
        "# Saudi Government Websites",
        "moe.gov.sa",
        "my.gov.sa", 
        "moi.gov.sa",
        "moh.gov.sa",
        "",
        "# Saudi Banks",
        "alrajhibank.com.sa",
        "sab.com",
        "riyadbank.com",
        "anb.com.sa",
        "",
        "# Arabic News Websites",
        "aljazeera.net",
        "arabnews.com",
        "alarabiya.net",
        "skynewsarabia.com"
    ]
    
    with open('urls_arabic.txt', 'w', encoding='utf-8') as f:
        for url in arabic_urls:
            f.write(url + '\n')
    
    print("✅ Created urls_arabic.txt with 14 Arabic websites")

def main():
    parser = argparse.ArgumentParser(
        description='🔐 Advanced HTTP Header Analyzer - Real Security Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-u', '--url', help='Single URL to analyze')
    parser.add_argument('-f', '--file', help='File containing URLs (one per line)')
    parser.add_argument('-o', '--output', default='analysis_results', help='Output filename (without extension)')
    parser.add_argument('--format', choices=['json', 'csv', 'html'], default='json', help='Output format')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--create-sample', action='store_true', help='Create sample urls.txt file')
    parser.add_argument('--create-arabic', action='store_true', help='Create Arabic URLs file')
    parser.add_argument('--arabic-report', action='store_true', help='Generate Arabic report')
    
    # New options for subdomain enumeration
    parser.add_argument('--enumerate', '-e', action='store_true', help='Enumerate subdomains before analysis')
    parser.add_argument('--domain', '-d', help='Main domain for subdomain enumeration')
    parser.add_argument('--max-subdomains', type=int, default=50, help='Maximum subdomains to analyze')
    parser.add_argument('--check-tools', action='store_true', help='Check availability of enumeration tools')
    parser.add_argument('--install-guide', action='store_true', help='Display tool installation guide')
    
    args = parser.parse_args()
    
    if args.create_sample:
        create_sample_urls_file()
        return
    
    if args.create_arabic:
        create_arabic_urls_file()
        return
    
    if args.check_tools or args.install_guide:
        enum = SubdomainEnumerator()
        print("\n🔍 Installed Tools Status:")
        print("="*50)
        for tool, available in enum.tools_available.items():
            status = "✅ Installed" if available else "❌ Not Installed"
            print(f"  {tool}: {status}")
        
        if args.install_guide or not any(enum.tools_available.values()):
            enum.install_tools_guide()
        return
    
    analyzer = HTTPHeaderAnalyzer()
    
    # If user requested subdomain enumeration
    if args.enumerate and args.domain:
        print(f"\n🔍 Starting subdomain enumeration for: {args.domain}")
        subdomains = analyzer.enumerate_subdomains(args.domain)
        
        if subdomains and len(subdomains) > 0:
            print(f"\n✅ Found {len(subdomains)} subdomains")
            
            # Analyze discovered subdomains
            response = input("\nDo you want to analyze the security of these subdomains? (y/n): ")
            if response.lower() == 'y':
                urls_to_analyze = list(subdomains)[:args.max_subdomains]
                print(f"\n🔐 Starting analysis of {len(urls_to_analyze)} subdomains...")
                
                for subdomain in urls_to_analyze:
                    analyzer.analyze_url(f"https://{subdomain}")
                    
        return
    
    if not args.url and not args.file:
        print("❌ Please specify a URL (-u) or file (-f)")
        print("\nExamples:")
        print("  python analyzer.py -u google.com")
        print("  python analyzer.py -f urls.txt")
        print("  python analyzer.py --create-sample")
        print("  python analyzer.py --create-arabic")
        print("  python analyzer.py -f urls_arabic.txt --arabic-report -o arabic_report")
        print("  python analyzer.py --enumerate --domain google.com --max-subdomains 20")
        print("  python analyzer.py --check-tools")
        return
    
    if args.url:
        analyzer.analyze_url(args.url)
        
    elif args.file:
        try:
            if not os.path.exists(args.file):
                print(f"❌ File '{args.file}' not found!")
                print("\n💡 Tip: Create a sample file with:")
                print("  python analyzer.py --create-sample")
                print("  python analyzer.py --create-arabic")
                return
                
            with open(args.file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            print(f"\n📋 Found {len(urls)} URLs in {args.file}")
            print(f"🚀 Starting analysis with {args.threads} threads...\n")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(analyzer.analyze_url, url) for url in urls]
                concurrent.futures.wait(futures)
                        
        except Exception as e:
            print(f"❌ Error: {e}")
            return
    
    # Save results
    if analyzer.results:
        if args.format == 'html' or args.arabic_report:
            analyzer.generate_arabic_report(args.output)
        else:
            analyzer.save_results(args.output, args.format)
        
        # Final summary
        print(f"\n{'='*60}")
        print("📊 Final Statistics")
        print(f"{'='*60}")
        print(f"  • Total Websites Analyzed: {analyzer.statistics['total']}")
        print(f"  • Websites with HSTS: {analyzer.statistics['hsts']}")
        print(f"  • Websites with X-Frame-Options: {analyzer.statistics['xframe']}")
        print(f"  • Websites with CSP: {analyzer.statistics['csp']}")
        print(f"  • Secure Cookies: {analyzer.statistics['secure_cookies']}")
        print(f"  • Valid SSL Certificates: {analyzer.statistics['ssl_valid']}")
        print(f"  • SSL Expiring Soon: {analyzer.statistics['ssl_expiring_soon']}")
        print(f"  • Subdomains Discovered: {analyzer.statistics['subdomains_found']}")

if __name__ == "__main__":
    main()