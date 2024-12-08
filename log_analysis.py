import re
import csv
from collections import Counter, defaultdict

FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def analyze_logs(file_path):
    ip_data = Counter()
    endpoint_data = Counter()
    failed_logins = defaultdict(int)

    pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>/\S*) HTTP/1.1" (?P<status>\d{3}) .*')
    failed_login_marker = re.compile(r"401|Invalid credentials")

    with open(file_path, 'r') as log_file:
        for line in log_file:
            entry = pattern.match(line)
            if entry:
                ip = entry.group("ip")
                endpoint = entry.group("endpoint")
                status_code = entry.group("status")

                ip_data[ip] += 1
                endpoint_data[endpoint] += 1

                if failed_login_marker.search(line):
                    failed_logins[ip] += 1

    return ip_data, endpoint_data, failed_logins

def write_to_csv(ip_summary, top_endpoint, flagged_ips, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(["Requests by IP"])
        writer.writerow(["IP Address", "Count"])
        for ip, count in ip_summary.items():
            writer.writerow([ip, count])
        writer.writerow([])

        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([top_endpoint[0], top_endpoint[1]])
        writer.writerow([])

        writer.writerow(["Potential Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in flagged_ips.items():
            writer.writerow([ip, count])

def main():
    ip_summary, endpoint_summary, failed_login_summary = analyze_logs(LOG_FILE)

    top_endpoint = endpoint_summary.most_common(1)[0]
    suspicious_ips = {ip: count for ip, count in failed_login_summary.items() if count > FAILED_LOGIN_THRESHOLD}

    print("Request Counts by IP:")
    for ip, count in ip_summary.most_common():
        print(f"{ip}: {count}")
    print("\nMost Accessed Endpoint:")
    print(f"{top_endpoint[0]} - {top_endpoint[1]} accesses")
    print("\nSuspicious IPs:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} failed attempts")

    write_to_csv(ip_summary, top_endpoint, suspicious_ips, OUTPUT_FILE)
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
