#!/usr/bin/env python3
"""
Quick test script to verify Medusa attack simulator setup
"""

import os
from pathlib import Path
import json

def test_setup():
    """Verify all required files and configurations exist"""
    
    print("🧪 Testing Medusa Attack Simulator Setup...")
    print("=" * 60)
    
    base_dir = Path(__file__).parent
    checks = []
    
    # Check 1: Wordlists directory
    wordlist_dir = base_dir / "wordlists"
    if wordlist_dir.exists():
        print("✅ Wordlists directory exists")
        checks.append(True)
    else:
        print("❌ Wordlists directory NOT found")
        checks.append(False)
    
    # Check 2: Username wordlist
    username_file = wordlist_dir / "usernames.txt"
    if username_file.exists():
        with open(username_file, 'r') as f:
            count = len(f.readlines())
        print(f"✅ Username wordlist exists ({count} entries)")
        checks.append(True)
    else:
        print("❌ Username wordlist NOT found")
        checks.append(False)
    
    # Check 3: Password wordlist
    password_file = wordlist_dir / "passwords.txt"
    if password_file.exists():
        with open(password_file, 'r') as f:
            count = len(f.readlines())
        print(f"✅ Password wordlist exists ({count} entries)")
        checks.append(True)
    else:
        print("❌ Password wordlist NOT found")
        checks.append(False)
    
    # Check 4: Config directory
    config_dir = base_dir / "attack_configs"
    if config_dir.exists():
        print("✅ Attack configs directory exists")
        checks.append(True)
    else:
        print("❌ Attack configs directory NOT found")
        checks.append(False)
    
    # Check 5: Medusa config
    medusa_config = config_dir / "medusa_config.json"
    if medusa_config.exists():
        with open(medusa_config, 'r') as f:
            config = json.load(f)
        attack_types = list(config.keys())
        print(f"✅ Medusa config exists (attack types: {', '.join(attack_types)})")
        checks.append(True)
    else:
        print("❌ Medusa config NOT found")
        checks.append(False)
    
    # Check 6: Discord webhook
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    if webhook_url:
        print(f"✅ Discord webhook configured")
        checks.append(True)
    else:
        print("⚠️  Discord webhook NOT configured (optional)")
        checks.append(True)  # Not critical
    
    # Check 7: attack_simulator.py
    simulator_file = base_dir / "attack_simulator.py"
    if simulator_file.exists():
        with open(simulator_file, 'r') as f:
            content = f.read()
            has_medusa = 'simulate_brute_force_medusa' in content
        if has_medusa:
            print("✅ attack_simulator.py has Medusa methods")
            checks.append(True)
        else:
            print("❌ attack_simulator.py missing Medusa methods")
            checks.append(False)
    else:
        print("❌ attack_simulator.py NOT found")
        checks.append(False)
    
    # Check 8: Documentation
    guide_file = base_dir / "MEDUSA_ATTACK_GUIDE.md"
    if guide_file.exists():
        print("✅ MEDUSA_ATTACK_GUIDE.md exists")
        checks.append(True)
    else:
        print("⚠️  MEDUSA_ATTACK_GUIDE.md NOT found")
        checks.append(False)
    
    print("=" * 60)
    
    # Summary
    passed = sum(checks)
    total = len(checks)
    percentage = (passed / total) * 100
    
    print(f"\n📊 Test Results: {passed}/{total} checks passed ({percentage:.1f}%)")
    
    if percentage == 100:
        print("🎉 All checks passed! Ready to run attacks.")
        print("\n💡 Try: python attack_simulator.py --attack medusa-http --iterations 5")
    elif percentage >= 80:
        print("⚠️  Most checks passed. Review warnings above.")
    else:
        print("❌ Setup incomplete. Please fix the errors above.")
    
    return percentage == 100

if __name__ == "__main__":
    test_setup()
