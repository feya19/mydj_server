#!/usr/bin/env python3
"""
Attack Simulation Script for mydj_server Security Testing
Based on the project documentation attack scenarios
"""

import requests
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse

# Configuration
API_BASE_URL = "http://localhost:8000"
ELASTICSEARCH_URL = "http://localhost:9200"

class AttackSimulator:
    def __init__(self):
        self.session = requests.Session()
    
    def log_to_elasticsearch(self, attack_type, source_ip, details):
        """Log attack to Elasticsearch for monitoring"""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        
        rule_mapping = {
            "sql_injection": {"id": 100001, "level": 12, "description": "SQL Injection attempt detected on mydj_server"},
            "brute_force": {"id": 100004, "level": 10, "description": "Multiple failed login attempts - Brute force attack detected"},
            "dos_attack": {"id": 100003, "level": 8, "description": "API Rate limit exceeded - Possible DoS attempt"},
            "port_scan": {"id": 100005, "level": 7, "description": "Port scanning activity detected"}
        }
        
        alert_data = {
            "@timestamp": timestamp,
            "rule": rule_mapping.get(attack_type, {"id": 99999, "level": 5, "description": "Unknown attack type"}),
            "data": {
                "srcip": source_ip,
                **details
            },
            "agent": {
                "name": "mydj_server"
            }
        }
        
        try:
            response = requests.post(
                f"{ELASTICSEARCH_URL}/wazuh-alerts/_doc",
                headers={"Content-Type": "application/json"},
                json=alert_data
            )
            print(f"✅ Logged {attack_type} attack to Elasticsearch: {response.status_code}")
        except Exception as e:
            print(f"❌ Failed to log to Elasticsearch: {e}")

    def simulate_sql_injection(self, iterations=5):
        """Test Case 3: SQL Injection attacks"""
        print(f"\n🔍 Starting SQL Injection simulation ({iterations} attempts)...")
        
        payloads = [
            "1' OR '1'='1'--",
            "1' UNION SELECT NULL--",
            "'; DROP TABLE users;--",
            "1' OR 1=1#",
            "admin'--"
        ]
        
        for i in range(iterations):
            payload = payloads[i % len(payloads)]
            data = {
                'kelas': payload,
                'mapel': 'test',
                'jam': 1,
                'tujuanPembelajaran': 'test',
                'materiTopikPembelajaran': 'test', 
                'kegiatanPembelajaran': 'test',
                'dimensiProfilPelajarPancasila': 'test',
                'createdAt': '2025-12-07'
            }
            
            try:
                response = self.session.post(f"{API_BASE_URL}/upload-jurnal", data=data)
                print(f"   SQL Injection {i+1}: {response.status_code} - Payload: {payload}")
                
                # Log to Elasticsearch
                self.log_to_elasticsearch("sql_injection", f"192.168.1.{100+i}", {
                    "url": "/upload-jurnal",
                    "payload": payload,
                    "status_code": response.status_code
                })
                
            except Exception as e:
                print(f"   ❌ SQL Injection {i+1} failed: {e}")
            
            time.sleep(1)

    def simulate_api_flooding(self, iterations=100, threads=10):
        """Test Case 4: API Flooding (DoS) attacks"""
        print(f"\n🌊 Starting API Flooding simulation ({iterations} requests, {threads} threads)...")
        
        def flood_request(request_id):
            data = {
                'kelas': f'flood_test_{request_id}',
                'mapel': 'test',
                'jam': 1,
                'tujuanPembelajaran': 'test',
                'materiTopikPembelajaran': 'test',
                'kegiatanPembelajaran': 'test', 
                'dimensiProfilPelajarPancasila': 'test',
                'createdAt': '2025-12-07'
            }
            
            try:
                response = self.session.post(f"{API_BASE_URL}/upload-jurnal", data=data)
                if request_id % 10 == 0:
                    print(f"   Request {request_id}: {response.status_code}")
                
                # Log rate limit hits
                if response.status_code == 429:
                    self.log_to_elasticsearch("dos_attack", f"192.168.1.{150 + (request_id % 10)}", {
                        "endpoint": "/upload-jurnal", 
                        "status_code": 429,
                        "request_id": request_id
                    })
                    
            except Exception as e:
                print(f"   ❌ Request {request_id} failed: {e}")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(flood_request, range(iterations))

    def simulate_brute_force(self, iterations=10):
        """Test Case 2: SSH Brute Force (simulated via API)"""
        print(f"\n🔓 Starting Brute Force simulation ({iterations} attempts)...")
        
        # Since we don't have authentication endpoint, we'll simulate via logs
        for i in range(iterations):
            source_ip = f"192.168.1.{200 + i}"
            
            # Log failed authentication attempt
            self.log_to_elasticsearch("brute_force", source_ip, {
                "event_type": "authentication_failed",
                "username": f"user{i}",
                "attempt": i + 1
            })
            
            print(f"   Brute Force {i+1}: Logged failed auth from {source_ip}")
            time.sleep(0.5)

    def simulate_port_scanning(self, iterations=3):
        """Test Case 1: Port Scanning"""
        print(f"\n🔍 Starting Port Scanning simulation ({iterations} scans)...")
        
        tools = ["nmap", "masscan", "zmap"]
        
        for i in range(iterations):
            source_ip = f"192.168.1.{300 + i}"
            tool = tools[i % len(tools)]
            
            # Log port scanning activity
            self.log_to_elasticsearch("port_scan", source_ip, {
                "tool": tool,
                "ports_scanned": "1-65535",
                "scan_type": "TCP SYN"
            })
            
            print(f"   Port Scan {i+1}: {tool} from {source_ip}")
            time.sleep(1)

    def check_api_status(self):
        """Check if the API is accessible"""
        try:
            response = self.session.get(f"{API_BASE_URL}/")
            if response.status_code == 200:
                print(f"✅ API is accessible: {response.json()}")
                return True
            else:
                print(f"❌ API returned status {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Cannot connect to API: {e}")
            return False

    def run_all_attacks(self):
        """Run all attack scenarios"""
        print("🚀 Starting mydj_server Security Testing...")
        print("=" * 60)
        
        if not self.check_api_status():
            return
        
        # Test Case 1: Port Scanning
        self.simulate_port_scanning(3)
        
        # Test Case 2: SSH Brute Force (simulated)
        self.simulate_brute_force(5)
        
        # Test Case 3: SQL Injection
        self.simulate_sql_injection(5)
        
        # Test Case 4: API Flooding
        self.simulate_api_flooding(50, 5)
        
        print("\n" + "=" * 60)
        print("🎯 All attack simulations completed!")
        print("📊 Check Kibana dashboard at: http://localhost:5602")
        print("🔍 Check Elasticsearch at: http://localhost:9200/wazuh-alerts/_search")

def main():
    parser = argparse.ArgumentParser(description='mydj_server Security Testing Tool')
    parser.add_argument('--attack', choices=['sql', 'dos', 'brute', 'scan', 'all'], 
                       default='all', help='Type of attack to simulate')
    parser.add_argument('--iterations', type=int, default=5, 
                       help='Number of iterations for the attack')
    
    args = parser.parse_args()
    
    simulator = AttackSimulator()
    
    if args.attack == 'sql':
        simulator.simulate_sql_injection(args.iterations)
    elif args.attack == 'dos':
        simulator.simulate_api_flooding(args.iterations * 10, 5)
    elif args.attack == 'brute':
        simulator.simulate_brute_force(args.iterations)
    elif args.attack == 'scan':
        simulator.simulate_port_scanning(args.iterations)
    else:
        simulator.run_all_attacks()

if __name__ == "__main__":
    main()