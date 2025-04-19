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
    elif traffic_type == '2':  # DNS Queries (Implement this function similarly)
        pass
    elif traffic_type == '3':  # Malicious TCP Connections (Implement this function similarly)
        pass
    elif traffic_type == '4':  # All Traffic
        pass
    elif traffic_type == '5':  # TCP Payload
        pass
    elif traffic_type == '6':  # UDP Payload
        pass

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
