#!/usr/bin/env python3
"""
Attack Simulation Script for mydj_server Security Testing
Enhanced with Medusa brute-force capabilities
Based on the project documentation attack scenarios
"""

import requests
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
import subprocess
import os
from pathlib import Path
from discord_notifier import DiscordNotifier

# Configuration
API_BASE_URL = "http://localhost:8000"
# Use container hostname for Elasticsearch when running in Docker
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1080148082404114513/Ybji_FHuLTha1Z2EhwiCUy0SY8MMBjiUgT70FPtzkjkcAgoNB-BSXxvE-ax2YH3Jhf_c")




class AttackSimulator:
    def __init__(self):
        self.session = requests.Session()
        self.discord = DiscordNotifier(DISCORD_WEBHOOK_URL) if DISCORD_WEBHOOK_URL else None
        self.base_dir = Path(__file__).parent
        self.wordlist_dir = self.base_dir / "wordlists"
        self.config_dir = self.base_dir / "attack_configs"
        
        # Load Medusa configuration
        self.medusa_config = self._load_medusa_config()
    
    def _load_medusa_config(self):
        """Load Medusa configuration from JSON file"""
        config_file = self.config_dir / "medusa_config.json"
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"⚠️  Medusa config not found at {config_file}, using defaults")
            return {
                "general": {
                    "wordlist_dir": "wordlists",
                    "username_file": "usernames.txt",
                    "password_file": "passwords.txt"
                }
            }

    
    def log_to_elasticsearch(self, attack_type, source_ip, details):
        """Log attack to Elasticsearch for monitoring"""
        # Use GMT+7 (Asia/Jakarta) timezone
        from datetime import datetime, timezone, timedelta
        gmt_plus_7 = timezone(timedelta(hours=7))
        timestamp = datetime.now(gmt_plus_7).strftime("%Y-%m-%dT%H:%M:%S.000+07:00")
        
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

    def simulate_brute_force_medusa(self, attack_type="http", iterations=10):
        """
        Test Case 2: Brute Force using Medusa
        
        Args:
            attack_type: Type of attack (http, ssh, ftp)
            iterations: Number of credential combinations to try
        """
        print(f"\n🔓 Starting Medusa Brute Force simulation ({attack_type}, {iterations} attempts)...")
        
        # Send Discord notification - Attack Start
        if self.discord:
            self.discord.send_embed(
                title="🚨 Medusa Brute-Force Attack Started",
                description=f"Initiating {attack_type.upper()} brute-force attack simulation",
                color="security",
                fields=[
                    {"name": "🎯 Attack Type", "value": attack_type.upper(), "inline": True},
                    {"name": "🔢 Max Attempts", "value": str(iterations), "inline": True},
                    {"name": "🛠️ Tool", "value": "Medusa", "inline": True}
                ],
                footer="MyDJ Server - Security Testing"
            )
        
        # Get wordlist paths
        username_file = self.wordlist_dir / self.medusa_config["general"]["username_file"]
        password_file = self.wordlist_dir / self.medusa_config["general"]["password_file"]
        
        if not username_file.exists() or not password_file.exists():
            print(f"❌ Wordlists not found!")
            print(f"   Expected: {username_file} and {password_file}")
            return
        
        # Prepare Medusa command based on attack type
        if attack_type == "http":
            # HTTP form-based brute-force
            config = self.medusa_config.get("http_form", {})
            target = config.get("target", "localhost")
            port = config.get("port", 8000)
            
            # Medusa HTTP module command
            # Note: Medusa's http module syntax
            cmd = [
                "medusa",
                "-h", target,
                "-n", str(port),
                "-U", str(username_file),
                "-P", str(password_file),
                "-M", "http",
                "-m", f"DIR:/upload-jurnal",
                "-t", str(config.get("threads", 4)),
                "-f"  # Stop on first success
            ]
            
        elif attack_type == "ssh":
            config = self.medusa_config.get("ssh", {})
            target = config.get("target", "localhost")
            port = config.get("port", 22)
            
            cmd = [
                "medusa",
                "-h", target,
                "-n", str(port),
                "-U", str(username_file),
                "-P", str(password_file),
                "-M", "ssh",
                "-t", str(config.get("threads", 4)),
                "-f"
            ]
            
        elif attack_type == "ftp":
            config = self.medusa_config.get("ftp", {})
            target = config.get("target", "localhost")
            port = config.get("port", 21)
            
            cmd = [
                "medusa",
                "-h", target,
                "-n", str(port),
                "-U", str(username_file),
                "-P", str(password_file),
                "-M", "ftp",
                "-t", str(config.get("threads", 4)),
                "-f"
            ]
        else:
            print(f"❌ Unknown attack type: {attack_type}")
            return
        
        print(f"📝 Executing Medusa command:")
        print(f"   {' '.join(cmd)}")
        
        # Execute Medusa attack
        start_time = time.time()
        successful_attempts = 0
        failed_attempts = 0
        
        try:
            # Run Medusa
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 60 second timeout
            )
            
            duration = time.time() - start_time
            
            # Parse Medusa output
            output = result.stdout + result.stderr
            print(f"\n📊 Medusa Output:")
            print(output)
            
            # Count attempts from output
            for line in output.split('\n'):
                if 'SUCCESS' in line.upper():
                    successful_attempts += 1
                elif 'FAILED' in line.upper() or 'ERROR' in line.upper():
                    failed_attempts += 1
            
            # Log to Elasticsearch
            for i in range(min(iterations, 10)):  # Log up to 10 attempts
                source_ip = f"192.168.1.{200 + i}"
                self.log_to_elasticsearch("brute_force", source_ip, {
                    "tool": "medusa",
                    "attack_type": attack_type,
                    "event_type": "brute_force_attempt",
                    "username": f"user{i}",
                    "attempt": i + 1,
                    "status": "failed",
                    "duration": duration
                })
            
            # Send Discord notification - Attack Complete
            if self.discord:
                self.discord.send_embed(
                    title="✅ Medusa Brute-Force Attack Completed",
                    description=f"{attack_type.upper()} brute-force simulation finished",
                    color="warning" if successful_attempts > 0 else "info",
                    fields=[
                        {"name": "🎯 Attack Type", "value": attack_type.upper(), "inline": True},
                        {"name": "⏱️ Duration", "value": f"{duration:.2f}s", "inline": True},
                        {"name": "✅ Successful", "value": str(successful_attempts), "inline": True},
                        {"name": "❌ Failed", "value": str(failed_attempts), "inline": True},
                        {"name": "📊 Total Attempts", "value": str(successful_attempts + failed_attempts), "inline": True}
                    ],
                    footer="MyDJ Server - Security Testing"
                )
            
            print(f"\n✅ Medusa attack completed:")
            print(f"   Duration: {duration:.2f}s")
            print(f"   Successful: {successful_attempts}")
            print(f"   Failed: {failed_attempts}")
            
        except subprocess.TimeoutExpired:
            print(f"⚠️  Medusa attack timed out after 60 seconds")
            if self.discord:
                self.discord.send_security_alert(
                    alert_type="Medusa Timeout",
                    ip_address="localhost",
                    details=f"{attack_type.upper()} brute-force attack timed out",
                    severity="warning"
                )
        except FileNotFoundError:
            print(f"❌ Medusa not found! Please install medusa:")
            print(f"   Ubuntu/Debian: sudo apt-get install medusa")
            print(f"   Or ensure it's in your PATH")
        except Exception as e:
            print(f"❌ Medusa attack failed: {e}")
            if self.discord:
                self.discord.send_error_notification(
                    error_type="Medusa Execution Error",
                    error_message=str(e)
                )

    def simulate_brute_force(self, iterations=10):
        """Legacy brute-force simulation (logs only, no actual attack)"""
        print(f"\n🔓 Starting Legacy Brute Force simulation ({iterations} attempts)...")
        
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
        """Run all attack scenarios including Medusa brute-force"""
        print("🚀 Starting mydj_server Security Testing...")
        print("=" * 60)
        
        if not self.check_api_status():
            return
        
        # Test Case 1: Port Scanning
        self.simulate_port_scanning(3)
        
        # Test Case 2a: Medusa HTTP Brute Force
        self.simulate_brute_force_medusa("http", 10)
        
        # Test Case 2b: Medusa SSH Brute Force (simulated)
        self.simulate_brute_force_medusa("ssh", 5)
        
        # Test Case 3: SQL Injection
        self.simulate_sql_injection(5)
        
        # Test Case 4: API Flooding
        self.simulate_api_flooding(50, 5)
        
        print("\n" + "=" * 60)
        print("🎯 All attack simulations completed!")
        print("📊 Check Kibana dashboard at: http://localhost:5602")
        print("🔍 Check Elasticsearch at: http://localhost:9200/wazuh-alerts/_search")
        print("💬 Check Discord for attack notifications")


def main():
    parser = argparse.ArgumentParser(
        description='mydj_server Security Testing Tool with Medusa',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all attacks
  python attack_simulator.py --attack all
  
  # Run Medusa HTTP brute-force
  python attack_simulator.py --attack medusa-http --iterations 20
  
  # Run Medusa SSH brute-force
  python attack_simulator.py --attack medusa-ssh --iterations 10
  
  # Run SQL injection test
  python attack_simulator.py --attack sql --iterations 5
        """
    )
    
    parser.add_argument(
        '--attack', 
        choices=['sql', 'dos', 'brute', 'scan', 'medusa-http', 'medusa-ssh', 'medusa-ftp', 'all'], 
        default='all', 
        help='Type of attack to simulate'
    )
    parser.add_argument(
        '--iterations', 
        type=int, 
        default=5, 
        help='Number of iterations for the attack'
    )
    
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
    elif args.attack == 'medusa-http':
        simulator.simulate_brute_force_medusa('http', args.iterations)
    elif args.attack == 'medusa-ssh':
        simulator.simulate_brute_force_medusa('ssh', args.iterations)
    elif args.attack == 'medusa-ftp':
        simulator.simulate_brute_force_medusa('ftp', args.iterations)
    else:
        simulator.run_all_attacks()

if __name__ == "__main__":
    main()
