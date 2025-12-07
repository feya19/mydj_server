#!/usr/bin/env python3
"""
Dashboard Data Generator for mydj_server Security Monitoring
Creates realistic security event data for comprehensive dashboard testing
"""

import requests
import json
import time
import random
from datetime import datetime, timedelta

ELASTICSEARCH_URL = "http://localhost:9200"

class DashboardDataGenerator:
    def __init__(self):
        self.attack_sources = [
            "192.168.1.100", "10.0.0.50", "172.16.1.200", "192.168.1.101",
            "203.0.113.45", "198.51.100.23", "192.0.2.100", "10.0.0.75"
        ]
        
        self.sql_payloads = [
            "1' OR '1'='1'--", "'; DROP TABLE users;--", "1' UNION SELECT NULL--",
            "admin'--", "' OR 1=1#", "1' OR '1'='1' /*", "'; INSERT INTO users--",
            "1'; DELETE FROM logs--", "' UNION SELECT password FROM users--"
        ]
        
        self.scan_tools = ["nmap", "masscan", "zmap", "unicornscan", "hping3"]
        self.endpoints = ["/upload-jurnal", "/api/auth", "/api/users", "/api/data", "/admin"]
        self.usernames = ["admin", "root", "user", "test", "guest", "administrator"]

    def generate_timestamp(self, hours_ago=0, minutes_ago=0):
        """Generate timestamp for events"""
        now = datetime.utcnow() - timedelta(hours=hours_ago, minutes=minutes_ago)
        return now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def inject_sql_injection_events(self, count=20):
        """Generate SQL injection attack events with variations"""
        print(f"🔍 Generating {count} SQL Injection events...")
        
        for i in range(count):
            hours_ago = random.randint(0, 23)
            minutes_ago = random.randint(0, 59)
            
            event_data = {
                "@timestamp": self.generate_timestamp(hours_ago, minutes_ago),
                "rule": {
                    "id": 100001,
                    "level": 12,
                    "description": "SQL Injection attempt detected on mydj_server",
                    "groups": ["web", "sql_injection", "attack"]
                },
                "data": {
                    "srcip": random.choice(self.attack_sources),
                    "url": random.choice(self.endpoints),
                    "payload": random.choice(self.sql_payloads),
                    "status_code": random.choice([200, 400, 403, 500]),
                    "user_agent": "sqlmap/1.6.12#stable" if random.random() > 0.7 else "Mozilla/5.0"
                },
                "agent": {"name": "mydj_server"},
                "location": f"/var/log/mydj_server/security.log",
                "severity": "critical"
            }
            
            self._send_to_elasticsearch(event_data)
            time.sleep(0.1)

    def inject_brute_force_events(self, count=15):
        """Generate brute force attack events"""
        print(f"🔓 Generating {count} Brute Force events...")
        
        for i in range(count):
            hours_ago = random.randint(0, 12)
            minutes_ago = random.randint(0, 59)
            
            event_data = {
                "@timestamp": self.generate_timestamp(hours_ago, minutes_ago),
                "rule": {
                    "id": 100004,
                    "level": 10,
                    "description": "Multiple failed login attempts - Brute force attack detected",
                    "groups": ["authentication_failures", "brute_force", "attack"]
                },
                "data": {
                    "srcip": random.choice(self.attack_sources),
                    "event_type": "authentication_failed",
                    "username": random.choice(self.usernames),
                    "attempts": random.randint(5, 20),
                    "service": random.choice(["ssh", "web_login", "api_auth"]),
                    "protocol": random.choice(["TCP", "HTTP"])
                },
                "agent": {"name": "mydj_server"},
                "location": f"/var/log/auth.log",
                "severity": "high"
            }
            
            self._send_to_elasticsearch(event_data)
            time.sleep(0.1)

    def inject_dos_attack_events(self, count=25):
        """Generate DoS attack events"""
        print(f"🌊 Generating {count} DoS Attack events...")
        
        for i in range(count):
            hours_ago = random.randint(0, 6)
            minutes_ago = random.randint(0, 59)
            
            event_data = {
                "@timestamp": self.generate_timestamp(hours_ago, minutes_ago),
                "rule": {
                    "id": 100003,
                    "level": 8,
                    "description": "API Rate limit exceeded - Possible DoS attempt",
                    "groups": ["web", "dos", "attack"]
                },
                "data": {
                    "srcip": random.choice(self.attack_sources),
                    "status_code": 429,
                    "endpoint": random.choice(self.endpoints),
                    "request_count": random.randint(100, 1000),
                    "time_window": "60s",
                    "response_time": random.randint(1000, 5000)
                },
                "agent": {"name": "mydj_server"},
                "location": f"/var/log/mydj_server/access.log",
                "severity": "medium"
            }
            
            self._send_to_elasticsearch(event_data)
            time.sleep(0.1)

    def inject_port_scan_events(self, count=10):
        """Generate port scanning events"""
        print(f"🔍 Generating {count} Port Scanning events...")
        
        for i in range(count):
            hours_ago = random.randint(0, 24)
            minutes_ago = random.randint(0, 59)
            
            event_data = {
                "@timestamp": self.generate_timestamp(hours_ago, minutes_ago),
                "rule": {
                    "id": 100005,
                    "level": 7,
                    "description": "Port scanning activity detected",
                    "groups": ["reconnaissance", "port_scan", "attack"]
                },
                "data": {
                    "srcip": random.choice(self.attack_sources),
                    "tool": random.choice(self.scan_tools),
                    "ports_scanned": random.choice(["1-65535", "1-1024", "80,443,22,21,25"]),
                    "scan_type": random.choice(["TCP SYN", "TCP Connect", "UDP", "FIN"]),
                    "ports_found": random.randint(1, 10),
                    "scan_duration": random.randint(30, 300)
                },
                "agent": {"name": "mydj_server"},
                "location": f"/var/log/syslog",
                "severity": "low"
            }
            
            self._send_to_elasticsearch(event_data)
            time.sleep(0.1)

    def inject_successful_responses(self, count=50):
        """Generate normal activity for comparison"""
        print(f"✅ Generating {count} Normal Activity events...")
        
        for i in range(count):
            hours_ago = random.randint(0, 24)
            minutes_ago = random.randint(0, 59)
            
            event_data = {
                "@timestamp": self.generate_timestamp(hours_ago, minutes_ago),
                "rule": {
                    "id": 200001,
                    "level": 3,
                    "description": "Successful API request",
                    "groups": ["web", "success", "normal"]
                },
                "data": {
                    "srcip": random.choice(["192.168.1.10", "192.168.1.11", "192.168.1.12"]),
                    "status_code": random.choice([200, 201, 202]),
                    "endpoint": random.choice(self.endpoints),
                    "response_time": random.randint(50, 500),
                    "method": random.choice(["GET", "POST", "PUT"])
                },
                "agent": {"name": "mydj_server"},
                "location": f"/var/log/mydj_server/access.log",
                "severity": "info"
            }
            
            self._send_to_elasticsearch(event_data)
            time.sleep(0.05)

    def _send_to_elasticsearch(self, data):
        """Send data to Elasticsearch"""
        try:
            response = requests.post(
                f"{ELASTICSEARCH_URL}/wazuh-alerts/_doc",
                headers={"Content-Type": "application/json"},
                json=data
            )
            if response.status_code not in [200, 201]:
                print(f"❌ Failed to send data: {response.status_code}")
        except Exception as e:
            print(f"❌ Error sending to Elasticsearch: {e}")

    def create_index_template(self):
        """Create index template for better field mapping"""
        template = {
            "index_patterns": ["wazuh-alerts*"],
            "template": {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "rule": {
                            "properties": {
                                "id": {"type": "integer"},
                                "level": {"type": "integer"},
                                "description": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                                "groups": {"type": "keyword"}
                            }
                        },
                        "data": {
                            "properties": {
                                "srcip": {"type": "ip"},
                                "status_code": {"type": "integer"},
                                "payload": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                                "endpoint": {"type": "keyword"},
                                "tool": {"type": "keyword"}
                            }
                        },
                        "agent": {
                            "properties": {
                                "name": {"type": "keyword"}
                            }
                        },
                        "severity": {"type": "keyword"}
                    }
                }
            }
        }
        
        try:
            response = requests.put(
                f"{ELASTICSEARCH_URL}/_index_template/wazuh-alerts-template",
                headers={"Content-Type": "application/json"},
                json=template
            )
            print(f"✅ Index template created: {response.status_code}")
        except Exception as e:
            print(f"❌ Error creating template: {e}")

    def generate_comprehensive_dataset(self):
        """Generate a comprehensive dataset for dashboard testing"""
        print("🚀 Generating comprehensive security dataset for dashboard...")
        print("=" * 60)
        
        # Create index template first
        self.create_index_template()
        time.sleep(1)
        
        # Generate different types of events
        self.inject_sql_injection_events(20)
        self.inject_brute_force_events(15)
        self.inject_dos_attack_events(25)
        self.inject_port_scan_events(10)
        self.inject_successful_responses(50)
        
        print("\n" + "=" * 60)
        print("🎯 Dashboard dataset generation completed!")
        print("📊 Total events generated: ~120 events")
        print("🔍 Event distribution:")
        print("   - SQL Injection: 20 events (Critical)")
        print("   - Brute Force: 15 events (High)")
        print("   - DoS Attacks: 25 events (Medium)")
        print("   - Port Scans: 10 events (Low)")
        print("   - Normal Activity: 50 events (Info)")
        print("\n📈 Ready for dashboard visualization!")
        print("🌐 Access Kibana: http://localhost:5602")

def main():
    generator = DashboardDataGenerator()
    generator.generate_comprehensive_dataset()

if __name__ == "__main__":
    main()