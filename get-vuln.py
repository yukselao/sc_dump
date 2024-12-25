#!/usr/bin/env python3
import argparse
import os
import traceback
import requests, json, sys 
import urllib3
import logging
import pandas as pd


class scops:
    def __init__(self, logindata):
        self.logindata=logindata        
        self.IP=logindata["url"]
        self.set_authentication_headers()
        
    def set_authentication_headers(self):
        sc_access_key=self.logindata["access_key"]
        sc_secret_key=self.logindata["secret_key"]
        self.headers = {"Accept": "application/json",
                        "X-APIKey": "accesskey={access_key}; secretkey={secret_key}".format(
                            access_key=sc_access_key,
                            secret_key=sc_secret_key)}

    def getCredentials(self):
        ret=requests.get(url=self.IP+"rest/credential",headers=self.headers,verify=False)  
        out=json.dumps(ret.json(), indent = 3)
        logging.info(out)
        
    def getIpSummaryOutput(self):
        filter = {
    'query': {
        'description': '',
        'context': '',
        'status': -1,
        'createdTime': 0,
        'modifiedTime': 0,
        'groups': [],
        'type': 'vuln',
        'tool': 'sumip',
        'sourceType': 'cumulative',
        'startOffset': 0,
        'endOffset': 100000,
        'filters': [
            {
                'id': 'severity',
                'filterName': 'severity',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': '4,3,2',
            },
        ],
        'sortColumn': 'score',
        'sortDirection': 'desc',
        'vulnTool': 'sumip',
    },
    'sourceType': 'cumulative',
    'sortField': 'score',
    'sortDir': 'desc',
    'columns': [],
    'type': 'vuln',
}
        ret=requests.post(url=self.IP+"rest/analysis",headers=self.headers, json=filter, verify=False)  
        out=json.dumps(ret.json(), indent = 3)
        iplist=[]
        for ipsummaryresult in ret.json()["response"]["results"]:
            iplist.append(ipsummaryresult["ip"])
        return iplist
    def getIpDetails(self, ip):
        filter = {
    'query': {
        'name': '',
        'description': '',
        'context': '',
        'status': -1,
        'createdTime': 0,
        'modifiedTime': 0,
        'groups': [],
        'type': 'vuln',
        'tool': 'listvuln',
        'sourceType': 'cumulative',
        'startOffset': 0,
        'endOffset': 99999,
        'filters': [
            {
                'id': 'ip',
                'filterName': 'ip',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': ip,
            },
            {
                'id': 'severity',
                'filterName': 'severity',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': '4,3,2',
            },
        ],
        'vulnTool': 'listvuln',
    },
    'sourceType': 'cumulative',
    'columns': [],
    'type': 'vuln',
}
        ret = requests.post(url=self.IP+"rest/analysis", headers=self.headers, json=filter, verify=False)  
        
        try:
            response_data = ret.json()
            if not isinstance(response_data, dict):
                logging.error(f"Unexpected response format: {response_data}")
                return [], filter["query"]["filters"]
            
            if "response" not in response_data or "results" not in response_data["response"]:
                logging.error(f"Missing expected fields: {response_data}")
                return [], filter["query"]["filters"]
            
            vulnlist = []
            for vuln in response_data["response"]["results"]:
                vulnlist.append(vuln)
            return vulnlist, filter["query"]["filters"]
        
        except json.JSONDecodeError as e:
            logging.error(f"JSON parsing error: {e}")
            logging.error(f"Raw response: {ret.text}")
            return [], filter["query"]["filters"]
        
    def getVulnDetails(self, vuln, myfilter):
        protocol = {'ICMP':1,'TCP': 6, 'UDP':17, 'Unknown':0}
        myfilter.append({
                'id': 'pluginID',
                'filterName': 'pluginID',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': vuln["pluginID"],
            })
        myfilter.append(
            {
                'id': 'port',
                'filterName': 'port',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': vuln["port"],
            })
        myfilter.append(
            {
                'id': 'protocol',
                'filterName': 'protocol',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': protocol[vuln["protocol"]],
            })
        filter = {
    'query': {
        'name': '',
        'description': '',
        'context': '',
        'status': -1,
        'createdTime': 0,
        'modifiedTime': 0,
        'groups': [],
        'type': 'vuln',
        'tool': 'vulndetails',
        'sourceType': 'cumulative',
        'startOffset': 0,
        'endOffset': 10000,
        'filters': myfilter,
        'vulnTool': 'vulndetails',
    },
    'sourceType': 'cumulative',
    'columns': [],
    'type': 'vuln',
}
        ret=requests.post(url=self.IP+"rest/analysis",headers=self.headers, json=filter, verify=False) 
        try: 
            return ret.json()["response"]["results"][0]
        except:
            pass
        return ""

#response = requests.post('https://localhost:8443/rest/analysis', cookies=cookies, headers=headers, json=filter)

def main():
    logging.basicConfig()
    logging.root.setLevel(logging.INFO)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    parser = argparse.ArgumentParser(description='Tenable Security Center dump tool')
    parser.add_argument('-t', '--target', type=str, help='Target IP address', required=True)
    parser.add_argument('-d', '--debug', type=str, help='Debug mode', required=False, default="false")
    args = parser.parse_args()
    
    
    scLogin = {
        'url': os.getenv('SC_URL'),
        'access_key': os.getenv('ACCESS_KEY'),
        'secret_key': os.getenv('SECRET_KEY')
    }
    sc=scops(scLogin)
    iplist=sc.getIpSummaryOutput()
    # Create data list for DataFrame
    data_list = []
    
    i = 0
    for ip in iplist:
        if ip == args.target:
            logging.info("Target IP: {} found in the list".format(args.target))
            vulnlist, filters = sc.getIpDetails(ip)
            logging.info("Total vulnerabilities: {}".format(len(vulnlist)))
            for vuln in vulnlist:
                i += 1
                vuln_details_filter = filters.copy()
                vuln_details = sc.getVulnDetails(vuln, vuln_details_filter)
                severity = vuln["severity"]["name"]
                try:
                    solution = "solution" in vuln_details and vuln_details['solution'].replace(',', '&#44;').replace(';', '&#59;') or "N/A"
                    dnsName = "dnsName" in vuln_details and vuln_details['dnsName'] or "N/A"
                    exploitAvailable = "exploitAvailable" in vuln_details and vuln_details['exploitAvailable'] or "N/A"
                except Exception as e:
                    logging.error("Vulnerability details are not in expected format. {} {}".format(vuln["name"], ip))
                    traceback.print_exc()
                logstr = "{} {} {} {}".format(i,ip, vuln["name"], vuln_details['pluginID'])
                if args.debug == "true":
                    logging.info(logstr)
                #solution = vulndetail["solution"].replace(',', '&#44;').replace(';', '&#59;')

                vuln_name = vuln["name"].replace(',', '&#44;').replace(';', '&#59;')
                
                data_list.append({
                    'IP': ip,
                    'Vulnerability Name': vuln_name,
                    'Risk Level': vuln["severity"]["name"],
                    'Solution': solution,
                    'DNS Name': dnsName,
                    'severity': severity,
                    'Exploit Available': exploitAvailable
                })

    # Create DataFrame and save to Excel
    df = pd.DataFrame(data_list)
    excel_file = 'vulnerability_report.xlsx'
    
    # Use Excel writer with specific options
    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Vulnerabilities')
        # Auto-adjust columns width
        worksheet = writer.sheets['Vulnerabilities']
        for idx, col in enumerate(df.columns):
            max_length = max(
                df[col].astype(str).apply(len).max(),
                len(col)
            ) + 2
            worksheet.column_dimensions[chr(65 + idx)].width = max_length

    logging.info(f"Report has been saved to {excel_file}")

if __name__=="__main__":
    main()
