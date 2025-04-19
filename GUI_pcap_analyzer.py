import pyshark
import requests
import json
from flask import Flask, request, render_template_string
from ipaddress import ip_address

# Initialize Flask app
app = Flask(__name__)

# HTTP analysis function
def http_requests(pcap_file, api_key):
    test_list1 = []
    test_list2 = []
    for pkt in pcap_file:
        try:
            if "HTTP" in pkt:
                test_list1.append(
                    "A " + pkt.http.request_method + " request was made to resource " + pkt.http.request_uri + " at host " + pkt.http.host)
                test_list2 = sorted(set(test_list1))
        except AttributeError:
            pass
    return test_list2

# VirusTotal domain check function
def domain_check_VT(domain, api_key):
    urld = "https://www.virustotal.com/api/v3/domains/"
    headers = {"accept": "application/json",
               "x-apikey": api_key}

    vurld = urld + str(domain)
    response = requests.get(vurld, headers=headers)
    response_json = json.loads(response.content)
    result = ""
    try:
        if (response_json['data']['attributes']['last_analysis_stats']['malicious'] or
            response_json['data']['attributes']['last_analysis_stats']['suspicious']) > 0:
            result = f"{str(domain)} has {str(response_json['data']['attributes']['last_analysis_stats']['malicious'])} malicious hit(s)"
    except KeyError:
        result = "You may have exceeded your VirusTotal API QUOTA or API-KEY may be invalid"
    return result

# HTTP host analysis with VirusTotal check
def http_host_VTCheck(pcap_file, api_key):
    list1 = []
    list2 = []
    for pkt in pcap_file:
        try:
            if "HTTP" in pkt:
                list1.append(pkt.http.host)
                list2 = sorted(set(list1))
        except AttributeError:
            pass

    results = []
    for value in list2:
        result = domain_check_VT(value, api_key)
        if result:
            results.append(result)
    return results

# DNS Queries analysis
def dns_queries(pcap_file, api_key):
    dns_results = []
    for pkt in pcap_file:
        try:
            if "DNS" in pkt:
                query = pkt.dns.qry_name
                resolved_ip = pkt.dns.a
                if resolved_ip and not ip_address(resolved_ip).is_private:
                    dns_results.append(f"DNS Query: {query} resolved to {resolved_ip}")
        except AttributeError:
            pass
    return dns_results

# Malicious TCP Connections analysis
def malicious_tcp_connections(pcap_file, api_key):
    unique_ips = set()
    for pkt in pcap_file:
        try:
            if "TCP" in pkt:
                unique_ips.add(pkt.ip.src)
                unique_ips.add(pkt.ip.dst)
        except AttributeError:
            pass

    results = []
    for ip in unique_ips:
        if not ip_address(ip).is_private:
            result = domain_check_VT(ip, api_key)  # Reuse VirusTotal check for IPs
            if result:
                results.append(result)
    return results

# All Traffic analysis
def analyze_all_traffic(pcap_file, api_key):
    all_results = []
    all_results.extend(http_requests(pcap_file, api_key))
    all_results.extend(http_host_VTCheck(pcap_file, api_key))
    all_results.extend(dns_queries(pcap_file, api_key))
    all_results.extend(malicious_tcp_connections(pcap_file, api_key))
    return all_results

# TCP Payload analysis
def tcp_payload(pcap_file):
    payload_results = []
    for pkt in pcap_file:
        try:
            if "TCP" in pkt and hasattr(pkt.tcp, "payload"):
                payload = pkt.tcp.payload.replace(':', '')
                decoded_payload = bytes.fromhex(payload).decode('utf-8', errors='ignore')
                if decoded_payload.isascii():
                    payload_results.append(f"TCP Payload: {decoded_payload}")
        except AttributeError:
            pass
        except ValueError:
            pass
    return payload_results

# UDP Payload analysis
def udp_payload(pcap_file):
    payload_results = []
    for pkt in pcap_file:
        try:
            if "UDP" in pkt and hasattr(pkt.udp, "payload"):
                payload = pkt.udp.payload.replace(':', '')
                decoded_payload = bytes.fromhex(payload).decode('utf-8', errors='ignore')
                if decoded_payload.isascii():
                    payload_results.append(f"UDP Payload: {decoded_payload}")
        except AttributeError:
            pass
        except ValueError:
            pass
    return payload_results

@app.route('/', methods=['GET'])
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PCAP Analysis Tool</title>
    </head>
    <body>
        <h1>PCAP Traffic Analysis Tool</h1>
        <form action="/analyze" method="post" enctype="multipart/form-data">
            <label for="file">Choose PCAP file:</label>
            <input type="file" name="file" accept=".pcap,.pcapng" required><br><br>

            <label for="traffic_type">Select Traffic Type:</label>
            <select name="traffic_type">
                <option value="1">HTTP Requests</option>
                <option value="2">DNS Queries</option>
                <option value="3">Malicious TCP Connections</option>
                <option value="4">All Traffic (HTTP, DNS, TCP)</option>
                <option value="5">TCP Payload</option>
                <option value="6">UDP Payload</option>
            </select><br><br>

            <label for="api_key">VirusTotal API Key:</label>
            <input type="text" name="api_key" placeholder="Enter your VirusTotal API Key" required><br><br>

            <input type="submit" value="Analyze">
        </form>

        <h2>Analysis Results:</h2>
        <ul>
            {% for result in results %}
                <li>{{ result }}</li>
            {% endfor %}
        </ul>
    </body>
    </html>
    ''')

@app.route('/analyze', methods=['POST'])
def analyze():
    # Get the uploaded PCAP file and API key from the form
    pcap_file = request.files['file']
    traffic_type = request.form['traffic_type']
    api_key = request.form['api_key']
    
    # Save the uploaded file temporarily to process
    pcap_file_path = 'uploaded.pcap'
    pcap_file.save(pcap_file_path)

    # Use Pyshark to capture packets from the uploaded PCAP file
    pcap = pyshark.FileCapture(pcap_file_path)
    
    # Analyze based on the selected traffic type
    analysis_results = []
    if traffic_type == '1':  # HTTP Requests
        analysis_results = http_requests(pcap, api_key)
        analysis_results.extend(http_host_VTCheck(pcap, api_key))
    elif traffic_type == '2':  # DNS Queries
        analysis_results = dns_queries(pcap, api_key)
    elif traffic_type == '3':  # Malicious TCP Connections
        analysis_results = malicious_tcp_connections(pcap, api_key)
    elif traffic_type == '4':  # All Traffic
        analysis_results = analyze_all_traffic(pcap, api_key)
    elif traffic_type == '5':  # TCP Payload
        analysis_results = tcp_payload(pcap)
    elif traffic_type == '6':  # UDP Payload
        analysis_results = udp_payload(pcap)
    
    # Display the results in the webpage
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PCAP Analysis Tool - Results</title>
    </head>
    <body>
        <h1>PCAP Traffic Analysis Tool</h1>
        <h2>Analysis Results:</h2>
        <ul>
            {% for result in results %}
                <li>{{ result }}</li>
            {% endfor %}
        </ul>
        <br>
        <a href="/">Go back</a>
    </body>
    </html>
    ''', results=analysis_results)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)