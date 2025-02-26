from flask import Flask, request, jsonify, render_template, send_file
import subprocess
import requests
import whois
import socket
import pdfkit
import os

app = Flask(__name__, template_folder='templates')

# Konfigurasi wkhtmltopdf
PDFKIT_CONFIG = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')

# API Key VirusTotal (Ganti dengan API Key kamu)
VIRUSTOTAL_API_KEY = "3284a494b98bb90fafea7231774c266eba21b78ae300d6cdd081876f94f05a59"

def is_ip(address):
    """Cek apakah input adalah IP atau domain."""
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False

def virustotal_analysis(ip):
    """Ambil data dari VirusTotal dan sortir hanya engine_name dan result."""
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        data = response.json()
        
        if 'data' in data and 'attributes' in data['data']:
            scans = data['data']['attributes'].get('last_analysis_results', {})
            return {engine: result['result'] for engine, result in scans.items()}
        else:
            return {"error": "Invalid response format"}
    except Exception as e:
        return {"error": str(e)}

def network_analysis(target_ip):
    """Scan jaringan dengan Nmap."""
    try:
        result = subprocess.run(["nmap", target_ip], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"

def port_scan(target_ip):
    """Scan semua port terbuka pada IP target."""
    try:
        result = subprocess.run(["nmap", "-p-", target_ip], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"

def whois_lookup(domain):
    """WHOIS lookup untuk domain."""
    try:
        w = whois.whois(domain)
        return {key: value for key, value in w.items()}
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    target = request.form['target']
   
    if is_ip(target):
        result_data = {
            "nmap_result": network_analysis(target),
            "virustotal_data": virustotal_analysis(target),
            "port_scan_result": port_scan(target),
            "whois_result": None
        }
    else:
        result_data = {
            "nmap_result": None,
            "virustotal_data": None,
            "port_scan_result": None,
            "whois_result": whois_lookup(target)
        }

    return jsonify(result_data)

@app.route('/export', methods=['POST'])
def export():
    target = request.form['target']
    data = request.form['data']

    html_content = f"""
    <html>
    <head>
        <title>SecuriScan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: white; }}
            h2, h3 {{ color: #333; }}
            pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <h2>SecuriScan Report</h2>
        <h3>Target: {target}</h3>
        <pre>{data}</pre>
    </body>
    </html>
    """

    pdf_file = "/tmp/analysis_report.pdf"
    pdfkit.from_string(html_content, pdf_file, configuration=PDFKIT_CONFIG)

    return send_file(pdf_file, as_attachment=True, download_name="Security_Analysis_Report.pdf")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
