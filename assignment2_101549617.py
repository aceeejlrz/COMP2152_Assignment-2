"""
Author: Jezrel Dela Cruz
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping common port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:

    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter allows controlled access to the private __target attribute
    # without exposing it directly. This means we can add validation logic (like rejecting empty strings)
    # in one place, and all code that reads or sets the target automatically goes through that logic.
    # Direct attribute access would bypass validation and could lead to invalid states.

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool using class PortScanner(NetworkTool), which means it
# automatically gets the __target private attribute, the @property getter, and the @target.setter
# validation without rewriting any of that code. For example, when PortScanner calls
# super().__init__(target), the parent constructor handles storing and validating the target IP.
class PortScanner(NetworkTool):

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, if the program tried to scan a port on an unreachable machine, the socket
        # would raise a socket.error (or socket.timeout) exception that is unhandled. This would crash
        # the entire thread — and since we're using threading, it could silently kill a thread mid-scan
        # without completing the results list. Using try-except ensures each port scan fails gracefully.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple port scans to run concurrently instead of waiting for each one to
    # time out before starting the next. Without threads, scanning 1024 ports with a 1-second timeout
    # each could take over 17 minutes in the worst case. With threads, all ports are scanned nearly
    # simultaneously, reducing total scan time to just a few seconds.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)
        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(e)


def load_past_scans():
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        for row in rows:
            scan_id, target, port, status, service, scan_date = row
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
    except Exception:
        print("No past scans found.")
    finally:
        if conn:
            conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    target = input("Enter target IP address (press Enter for 127.0.0.1): ")
    if target == "":
        target = "127.0.0.1"

    try:
        start_port = int(input("Enter start port (1-1024): "))
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    if start_port < 1 or start_port > 1024:
        print("Port must be between 1 and 1024.")
        exit()

    try:
        end_port = int(input("Enter end port (1-1024): "))
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    if end_port < 1 or end_port > 1024:
        print("Port must be between 1 and 1024.")
        exit()

    if end_port < start_port:
        print("End port must be greater than or equal to start port.")
        exit()

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)
    open_ports = scanner.get_open_ports()

    print(f"--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: Open ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, open_ports)

    history = input("Would you like to see past scan history? (yes/no): ")
    if history.lower() == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# A useful addition would be a "port risk classifier" feature that loops through the open ports
# returned by get_open_ports() and classifies each one by security risk level. Ports in
# [21, 22, 23, 3389] are flagged as HIGH RISK, ports in [25, 110, 143, 3306] as MEDIUM RISK,
# and all others as LOW RISK. It uses a nested conditional list comprehension:
# risk_report = [
#     (p, s, "HIGH") if p in [21,22,23,3389]
#     else (p, s, "MEDIUM") if p in [25,110,143,3306]
#     else (p, s, "LOW")
#     for p, s, svc in open_ports
# ]
# The result is a risk report printed after every scan, giving users an instant security summary.
# Diagram: See diagram_101549617.png in the repository root
