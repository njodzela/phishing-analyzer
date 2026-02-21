import argparse
import email
from email import policy
import re
import os
import requests
import base64
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

def parse_args():
    parser = argparse.ArgumentParser(description="Phishing Analyzer - Extract IOCs and analyze an .eml file.")
    parser.add_argument("eml_file", help="Path to the .eml file to analyze.")
    parser.add_argument("--vt-api", help="VirusTotal API key.", default=os.getenv("VT_API_KEY"))
    parser.add_argument("--abuseipdb-api", help="AbuseIPDB API key.", default=os.getenv("ABUSEIPDB_API_KEY"))
    parser.add_argument("--output-html", help="Path to output HTML report.", default="report.html")
    return parser.parse_args()

def extract_ip_from_received(received_headers: List[str]) -> str:
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    for header in received_headers:
        ips = ip_pattern.findall(header)
        for ip in ips:
            if not ip.startswith(("10.", "127.", "192.168.")) and not re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip):
                return ip
    return None

def extract_urls(text: str) -> List[str]:
    url_pattern = re.compile(r'(https?://[^\s<"\']+)', re.IGNORECASE)
    return list(set(url_pattern.findall(text)))

def parse_eml(file_path: str) -> Dict[str, Any]:
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    
    extracted = {
        "sender": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "auth_results": msg.get("Authentication-Results", "None"),
        "received": msg.get_all("Received", []),
        "urls": [],
        "attachments": []
    }
    
    body_text = ""
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))
        
        if "attachment" in content_disposition or part.get_filename():
            filename = part.get_filename()
            if filename:
                extracted["attachments"].append(filename)
                
        if content_type in ["text/plain", "text/html"]:
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text += payload.decode(errors='ignore') + "\n"
            except:
                pass
                
    extracted["urls"] = extract_urls(body_text)
    extracted["sender_ip"] = extract_ip_from_received(extracted["received"])
    
    return extracted

def check_virustotal(url: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"status": "skipped", "reason": "No API key provided"}
    
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {"status": "success", "malicious": stats['malicious'], "suspicious": stats['suspicious'], "harmless": stats['harmless']}
        elif response.status_code == 404:
            return {"status": "not_found", "reason": "Not found in VT"}
        else:
            return {"status": "error", "reason": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "reason": "Request failed"}

def check_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"status": "skipped", "reason": "No API key provided"}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                "status": "success", 
                "abuse_score": data.get('abuseConfidenceScore', 0), 
                "country": data.get('countryCode', 'Unknown'),
                "isp": data.get('isp', 'Unknown')
            }
        else:
            return {"status": "error", "reason": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "reason": "Request failed"}

def calculate_risk(parsed_data: Dict[str, Any], vt_results: Dict[str, Any], ip_results: Dict[str, Any]) -> str:
    score = 0
    recs = []
    
    auth = parsed_data.get("auth_results", "").lower()
    if "fail" in auth or "softfail" in auth:
        score += 3
        recs.append("Email failed authentication checks (SPF/DKIM/DMARC). Verify the sender's identity.")
        
    for url, res in vt_results.items():
        if res.get("status") == "success":
            if res.get("malicious", 0) > 0:
                score += 5
                recs.append(f"URL {url} flagged as malicious by VirusTotal. DO NOT CLICK.")
            elif res.get("suspicious", 0) > 0:
                score += 2
                recs.append(f"URL {url} flagged as suspicious by VirusTotal.")
                
    if ip_results.get("status") == "success":
        abuse = ip_results.get("abuse_score", 0)
        if abuse > 50:
            score += 5
            recs.append(f"Sender IP has a high abuse confidence score ({abuse}%). Consider blocking at firewall.")
        elif abuse > 10:
            score += 2
            recs.append(f"Sender IP has some abuse history ({abuse}%). Monitor closely.")
            
    sender = parsed_data.get("sender", "").lower()
    reply_to = parsed_data.get("reply_to", "").lower()
    if reply_to and reply_to not in sender:
        score += 2
        recs.append("Reply-To address differs from Sender address. Common in phishing to redirect replies.")
        
    if parsed_data.get("attachments"):
        recs.append("Email contains attachments. Sandboxing or anti-malware scanning recommended before opening.")

    risk = "LOW"
    if score >= 8:
        risk = "CRITICAL"
    elif score >= 5:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
        
    if not recs:
        recs.append("No immediate threats identified, but always exercise caution.")
        
    return risk, recs

def generate_html_report(parsed_data, vt_results, ip_results, risk, recs, output_path):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Phishing Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
        h1 {{ border-bottom: 2px solid #0056b3; padding-bottom: 10px; color: #0056b3; }}
        h2 {{ color: #444; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
        .risk-badge {{ display: inline-block; padding: 10px 20px; color: white; border-radius: 4px; font-weight: bold; }}
        .CRITICAL {{ background-color: #dc3545; }}
        .HIGH {{ background-color: #fd7e14; }}
        .MEDIUM {{ background-color: #ffc107; color: #000; }}
        .LOW {{ background-color: #198754; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; table-layout: fixed; word-wrap: break-word; }}
        th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
        th {{ background-color: #f8f9fa; width: 25%; }}
        .list-items {{ margin: 0; padding-left: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Phishing Analyzer Report</h1>
        <h2>Overall Risk: <span class="risk-badge {risk}">{risk}</span></h2>
        
        <h2>Email Details</h2>
        <table>
            <tr><th>Sender</th><td>{parsed_data.get('sender', 'N/A')}</td></tr>
            <tr><th>Reply-To</th><td>{parsed_data.get('reply_to', 'N/A')}</td></tr>
            <tr><th>Subject</th><td>{parsed_data.get('subject', 'N/A')}</td></tr>
            <tr><th>Date</th><td>{parsed_data.get('date', 'N/A')}</td></tr>
            <tr><th>Authentication</th><td>{parsed_data.get('auth_results', 'N/A')}</td></tr>
            <tr><th>Sender IP</th><td>{parsed_data.get('sender_ip', 'N/A')}</td></tr>
        </table>

        <h2>Threat Intelligence Lookups</h2>
        <h3>AbuseIPDB (IP: {parsed_data.get('sender_ip', 'None')})</h3>
        <p>
"""
    if parsed_data.get('sender_ip') and ip_results:
        if ip_results.get('status') == 'success':
            html += f"Score: {ip_results.get('abuse_score')}%, Country: {ip_results.get('country')}, ISP: {ip_results.get('isp')}"
        else:
            html += f"Result: {ip_results.get('reason')}"
    else:
        html += "No IP found or checked."
        
    html += """
        </p>
        
        <h3>VirusTotal (URLs)</h3>
        <table>
            <tr><th>URL</th><th>Result</th></tr>
"""
    for u, res in vt_results.items():
        if res.get('status') == 'success':
            html += f"<tr><td>{u}</td><td>Malicious: {res.get('malicious')}, Suspicious: {res.get('suspicious')}, Harmless: {res.get('harmless')}</td></tr>"
        else:
            html += f"<tr><td>{u}</td><td>{res.get('reason')}</td></tr>"
    if not vt_results:
        html += "<tr><td colspan='2'>No URLs extracted.</td></tr>"

    html += """
        </table>

        <h2>Attachments</h2>
        <ul class="list-items">
"""
    for att in parsed_data.get('attachments', []):
        html += f"<li>{att}</li>"
    if not parsed_data.get('attachments'):
        html += "<li>None</li>"
        
    html += """
        </ul>

        <h2>Recommendations</h2>
        <ul class="list-items">
"""
    for r in recs:
        html += f"<li>{r}</li>"
        
    html += """
        </ul>
        <footer style="margin-top: 30px; font-size: 0.9em; color: #777;">Generated by Phishing Analyzer by Christian M. Njodzela</footer>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    args = parse_args()
    
    if not os.path.exists(args.eml_file):
        console.print(f"[bold red]Error[/bold red]: File {args.eml_file} not found.")
        return
        
    with console.status(f"[bold blue]Analyzing {args.eml_file}..."):
        eml_data = parse_eml(args.eml_file)
        
        vt_results = {}
        if eml_data["urls"]:
            for u in eml_data["urls"]:
                vt_results[u] = check_virustotal(u, args.vt_api)
                
        ip_results = {}
        if eml_data["sender_ip"]:
            ip_results = check_abuseipdb(eml_data["sender_ip"], args.abuseipdb_api)
            
        risk, recs = calculate_risk(eml_data, vt_results, ip_results)
        
    # Terminal Output
    console.print(Panel(Text("Phishing Analyzer Results", justify="center", style="bold magenta")))
    
    color = "green"
    if risk == "MEDIUM": color = "yellow"
    elif risk == "HIGH": color = "orange3"
    elif risk == "CRITICAL": color = "red"
        
    console.print(f"\n[bold]Overall Risk Score:[/bold] [{color}]{risk}[/{color}]")
    
    details_table = Table(title="Email Details", show_header=False, box=None)
    details_table.add_column("Field", style="bold cyan")
    details_table.add_column("Value")
    details_table.add_row("Sender", eml_data.get("sender", "N/A"))
    details_table.add_row("Reply-To", eml_data.get("reply_to", "N/A"))
    details_table.add_row("Subject", eml_data.get("subject", "N/A"))
    details_table.add_row("Date", eml_data.get("date", "N/A"))
    details_table.add_row("Auth Results", eml_data.get("auth_results", "N/A"))
    details_table.add_row("Origin IP", eml_data.get("sender_ip", "N/A"))
    console.print(details_table)
    
    console.print("\n[bold cyan]Threat Intelligence[/bold cyan]")
    if ip_results:
        if ip_results.get('status') == 'success':
            console.print(f"AbuseIPDB (IP {eml_data['sender_ip']}): Score {ip_results['abuse_score']}%, Country {ip_results['country']}, ISP {ip_results['isp']}")
        else:
            console.print(f"AbuseIPDB (IP {eml_data['sender_ip']}): {ip_results.get('reason')}")
    else:
        if not eml_data.get("sender_ip"):
            console.print("No External IP found in headers to check.")
            
    if vt_results:
        vt_table = Table(show_header=True)
        vt_table.add_column("URL", style="dim")
        vt_table.add_column("Result")
        for u, res in vt_results.items():
            if res.get('status') == 'success':
                res_text = f"[red]Malicious: {res['malicious']}[/red], [yellow]Suspicious: {res['suspicious']}[/yellow], [green]Harmless: {res['harmless']}[/green]"
                vt_table.add_row(u, res_text)
            else:
                vt_table.add_row(u, str(res.get('reason')))
        console.print(vt_table)
    else:
        console.print("No URLs extracted.")
        
    if eml_data.get("attachments"):
        console.print(f"\n[bold cyan]Attachments[/bold cyan]: {', '.join(eml_data['attachments'])}")
        
    console.print("\n[bold cyan]Recommendations for Analyst[/bold cyan]")
    for r in recs:
        console.print(f"- {r}")

    # Generate HTML
    generate_html_report(eml_data, vt_results, ip_results, risk, recs, args.output_html)
    console.print(f"\n[bold green]Report successfully generated at [white]{args.output_html}[/white][/bold green]")

if __name__ == "__main__":
    main()
