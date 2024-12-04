'''Web Server Log Analysis System
----------------------------------
A comprehensive log parsing utility designed to extract actionable insights from web server logs, 
providing robust traffic pattern analysis and advanced threat detection capabilities. Generates 
multi-format reporting across HTML, CSV, and terminal interfaces to support comprehensive 
cybersecurity and network performance monitoring.

Author: Mohammed Abdul Moiz '''

import re
import csv
from collections import Counter
from datetime import datetime
from typing import NamedTuple
from prettytable import PrettyTable

class LogEntry(NamedTuple):
    """Represents a single log entry"""
    ip: str
    timestamp: datetime
    method: str
    endpoint: str
    status: int
    size: int
    message: str

class LogAnalyzer:
    def __init__(self, failed_login_threshold: int = 3, 
                 output_csv_path: str = "log_analysis_results.csv", 
                 output_html_path: str = "log_analysis_report.html"):
        self.failed_login_threshold = failed_login_threshold
        self.output_csv_path = output_csv_path
        self.output_html_path = output_html_path
        self.log_pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+).*?\[(\d+/\w+/\d+:\d+:\d+:\d+\s[+\-]\d+)\]\s*"'
            r'(\w+)\s+([^\s]*)\s+HTTP/\d\.\d"\s+(\d+)\s+(\d+)(?:\s+"([^"]*)")?'
        )

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single log line into a LogEntry object"""
        match = self.log_pattern.match(line)
        if not match:
            return None
        
        ip, timestamp_str, method, endpoint, status, size, message = match.groups()
        timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        return LogEntry(
            ip=ip,
            timestamp=timestamp,
            method=method,
            endpoint=endpoint,
            status=int(status),
            size=int(size),
            message=message or ""
        )

    def analyze_logs(self, log_data: str):
        """Analyze the log data and generate reports"""
        # Initialize counters
        requests_per_ip = Counter()
        endpoint_hits = Counter()
        failed_logins = Counter()
        total_bandwidth = 0
        entries = []

        # Process each line
        for line in log_data.strip().split('\n'):
            entry = self.parse_line(line)
            if entry:
                entries.append(entry)
                requests_per_ip[entry.ip] += 1
                endpoint_hits[entry.endpoint] += 1
                total_bandwidth += entry.size
                
                if entry.status == 401 and "Invalid credentials" in entry.message:
                    failed_logins[entry.ip] += 1

        if not entries:
            print("No valid log entries found.")
            return

        # Generate reports
        self._print_summary(entries, total_bandwidth)
        self._print_ip_report(requests_per_ip)
        self._print_endpoint_report(endpoint_hits)
        self._print_security_report(failed_logins)

        # Export reports
        self._save_to_csv(requests_per_ip, endpoint_hits, failed_logins)
        self._save_to_html(entries, requests_per_ip, endpoint_hits, failed_logins, total_bandwidth)

    def _print_summary(self, entries, total_bandwidth):
        """Print general summary statistics"""
        print("\n=== Log Analysis Summary ===")
        print(f"Total Requests: {len(entries)}")
        print(f"Unique IPs: {len(set(entry.ip for entry in entries))}")
        print(f"Total Bandwidth Used: {total_bandwidth/1024:.2f} KB")
        print(f"Analysis Time Range: {entries[0].timestamp} to {entries[-1].timestamp}")

    def _print_ip_report(self, requests_per_ip):
        """Print IP address activity report"""
        print("\n=== IP Address Activity ===")
        table = PrettyTable()
        table.field_names = ["IP Address", "Request Count"]
        for ip, count in requests_per_ip.most_common():
            table.add_row([ip, count])
        print(table)

    def _print_endpoint_report(self, endpoint_hits):
        """Print endpoint popularity report"""
        print("\n=== Most Accessed Endpoints ===")
        table = PrettyTable()
        table.field_names = ["Endpoint", "Hit Count"]
        for endpoint, count in endpoint_hits.most_common():
            table.add_row([endpoint, count])
        print(table)

    def _print_security_report(self, failed_logins):
        """Print security-related findings"""
        suspicious_ips = {ip: count for ip, count in failed_logins.items() 
                        if count >= self.failed_login_threshold}
        
        if suspicious_ips:
            print("\n=== Security Alert: Suspicious Activity ===")
            table = PrettyTable()
            table.field_names = ["IP Address", "Failed Login Attempts"]
            for ip, count in suspicious_ips.items():
                table.add_row([ip, count])
            print(table)
            print("\nWARNING: These IPs have exceeded the failed login threshold "
                  f"of {self.failed_login_threshold} attempts")

    def _save_to_csv(self, requests_per_ip, endpoint_hits, failed_logins):
        """Export analysis results to CSV"""
        with open(self.output_csv_path, mode='w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            
            # Write Requests Per IP
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in requests_per_ip.most_common():
                writer.writerow([ip, count])
            
            # Write Most Frequently Accessed Endpoints
            writer.writerow([])
            writer.writerow(["Most Frequently Accessed Endpoints:", "Hit Count"])
            for endpoint, count in endpoint_hits.most_common():
                writer.writerow([endpoint, count])
            
            # Write Suspicious Activity
            writer.writerow([])
            writer.writerow(["Suspicious Activity Detected"])
            writer.writerow(["IP Address", "Failed Login Attempts"])
            suspicious_ips = {ip: count for ip, count in failed_logins.items() 
                            if count >= self.failed_login_threshold}
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])

    def _save_to_html(self, entries, requests_per_ip, endpoint_hits, failed_logins, total_bandwidth):
        """Generate HTML report"""
        with open(self.output_html_path, "w") as html_file:
            html_file.write("""
<html>
  <head>
    <title>Log Analysis Report</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin: 20px;
        background-color: #f4f4f9;
        color: #333;
      }
      h1, h2 {
        text-align: center;
        color: #0047ab;
      }
      table {
        width: 80%;
        margin: 20px auto;
        border-collapse: collapse;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        background-color: #ffffff;
      }
      th, td {
        border: 1px solid #dddddd;
        text-align: center;
        padding: 10px;
      }
      th {
        background-color: #0047ab;
        color: white;
        font-weight: bold;
      }
      tr:nth-child(even) {
        background-color: #f9f9f9;
      }
      tr:hover {
        background-color: #f1f1f1;
      }
      p {
        text-align: center;
        font-size: 18px;
        font-style: italic;
        color: #333;
      }
    </style>
  </head>
  <body>
    <h1>Log Analysis Report</h1>
""")
            # Summary Section
            html_file.write(f"""
    <h2>Summary Statistics</h2>
    <p>Total Requests: {len(entries)}</p>
    <p>Unique IPs: {len(set(entry.ip for entry in entries))}</p>
    <p>Total Bandwidth Used: {total_bandwidth/1024:.2f} KB</p>
    <p>Analysis Time Range: {entries[0].timestamp} to {entries[-1].timestamp}</p>
""")

            # Requests Per IP
            html_file.write("""
    <h2>Requests Per IP</h2>
    <table>
      <tr>
        <th>IP Address</th>
        <th>Request Count</th>
      </tr>
""")
            for ip, count in requests_per_ip.most_common():
                html_file.write(f"      <tr><td>{ip}</td><td>{count}</td></tr>\n")
            html_file.write("    </table>\n")

            # Most Accessed Endpoints
            html_file.write("""
    <h2>Most Accessed Endpoints</h2>
    <table>
      <tr>
        <th>Endpoint</th>
        <th>Hit Count</th>
      </tr>
""")
            for endpoint, count in endpoint_hits.most_common():
                html_file.write(f"      <tr><td>{endpoint}</td><td>{count}</td></tr>\n")
            html_file.write("    </table>\n")

            # Suspicious Activity
            suspicious_ips = {ip: count for ip, count in failed_logins.items() 
                            if count >= self.failed_login_threshold}
            html_file.write("""
    <h2>Suspicious Activity</h2>
""")
            if suspicious_ips:
                html_file.write("""
    <table>
      <tr>
        <th>IP Address</th>
        <th>Failed Login Attempts</th>
      </tr>
""")
                for ip, count in suspicious_ips.items():
                    html_file.write(f"      <tr><td>{ip}</td><td>{count}</td></tr>\n")
                html_file.write("    </table>\n")
            else:
                html_file.write("    <p>No suspicious activity detected.</p>\n")

            html_file.write("""
  </body>
</html>
""")
        print(f"\nResults saved to {self.output_csv_path} and {self.output_html_path}")

def main():
    # Hardcoded path to your log file
    log_file_path = r'C:\Users\pract\Desktop\VRV-Security-s-Python-Intern-Assignment-main\VRV\sample.log'
    
    try:
        # Read the log data from the file
        with open(log_file_path, 'r', encoding='utf-8') as file:
            log_data = file.read()
        
        # Create analyzer and process logs
        analyzer = LogAnalyzer(
            failed_login_threshold=3,
            output_csv_path="log_analysis_results.csv",
            output_html_path="log_analysis_report.html"
        )
        analyzer.analyze_logs(log_data)
    except FileNotFoundError:
        print(f"Error: Could not find log file '{log_file_path}'")
    except UnicodeDecodeError:
        print(f"Error: File encoding issue. Try opening the file with a different encoding.")
    except Exception as e:
        print(f"Error reading log file: {str(e)}")

if __name__ == "__main__":
    main()