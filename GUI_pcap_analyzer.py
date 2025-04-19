import pyshark
import requests
import json
import time
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
    start_time = time.time()  # Start timer
    response = requests.get(vurld, headers=headers)
    end_time = time.time()  # End timer

    response_time = end_time - start_time  # Calculate time taken
    response_json = json.loads(response.content)
    result = ""
    try:
        if (response_json['data']['attributes']['last_analysis_stats']['malicious'] or
            response_json['data']['attributes']['last_analysis_stats']['suspicious']) > 0:
            result = f"{str(domain)} has {str(response_json['data']['attributes']['last_analysis_stats']['malicious'])} malicious hit(s). Response Time: {response_time:.2f} seconds"
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

@app.route('/', methods=['GET'])
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PCAP Analysis Tool</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h1 class="text-center">PCAP Traffic Analysis Tool</h1>
            <form action="/analyze" method="post" enctype="multipart/form-data" id="analysisForm">
                <div class="mb-3">
                    <label for="file" class="form-label">Choose PCAP file:</label>
                    <input type="file" name="file" accept=".pcap,.pcapng" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="traffic_type" class="form-label">Select Traffic Type:</label>
                    <select name="traffic_type" class="form-select">
                        <option value="1">HTTP Requests</option>
                        <option value="2">DNS Queries</option>
                        <option value="3">Malicious TCP Connections</option>
                        <option value="4">All Traffic (HTTP, DNS, TCP)</option>
                    </select>
                </div>
                <div class="mb-3">
                    <label for="api_key" class="form-label">VirusTotal API Key:</label>
                    <input type="text" name="api_key" class="form-control" placeholder="Enter your VirusTotal API Key" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Analyze</button>
            </form>

            <div id="progressSection" class="mt-5" style="display: none;">
                <h3>Analysis in Progress...</h3>
                <div class="progress">
                    <div id="progressBar" class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width: 0%"></div>
                </div>
                <p id="timeLeft" class="mt-2">Estimated Time Left: <span id="timeEstimate">Calculating...</span></p>
            </div>
        </div>

        <script>
            document.getElementById("analysisForm").onsubmit = function () {
                document.getElementById("progressSection").style.display = "block";
                let progress = 0;
                let timeLeft = 20; // Assume 20 seconds for example
                const progressBar = document.getElementById("progressBar");
                const timeEstimate = document.getElementById("timeEstimate");

                const interval = setInterval(() => {
                    if (progress >= 100) {
                        clearInterval(interval);
                    } else {
                        progress += 5; // Increment progress
                        timeLeft -= 1; // Decrement time
                        progressBar.style.width = progress + "%";
                        timeEstimate.textContent = timeLeft + " seconds";
                    }
                }, 1000);
            };
        </script>
    </body>
    </html>
    ''')

@app.route('/analyze', methods=['POST'])
def analyze():
    pcap_file = request.files['file']
    traffic_type = request.form['traffic_type']
    api_key = request.form['api_key']
    
    pcap_file_path = 'uploaded.pcap'
    pcap_file.save(pcap_file_path)

    pcap = pyshark.FileCapture(pcap_file_path)
    
    if traffic_type == '1':
        analysis_results = http_requests(pcap, api_key)
    elif traffic_type == '2':
        analysis_results = dns_queries(pcap, api_key)
    elif traffic_type == '3':
        analysis_results = malicious_tcp_connections(pcap, api_key)
    elif traffic_type == '4':
        analysis_results = analyze_all_traffic(pcap, api_key)
    
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PCAP Analysis Tool - Results</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h1 class="text-center">PCAP Traffic Analysis Tool</h1>
            <h2>Analysis Results:</h2>
            <ul class="list-group">
                {% for result in results %}
                    <li class="list-group-item">{{ result }}</li>
                {% endfor %}
            </ul>
            <br>
            <a href="/" class="btn btn-secondary">Go back</a>
        </div>
    </body>
    </html>
    ''', results=analysis_results)

if __name__ == '__main__':
    app.run(debug=True)
