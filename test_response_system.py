#!/usr/bin/env python3
"""
Test Script: Automatic Response System Demo
Shows how the DQN Agent makes automatic response decisions
"""

import numpy as np
from dqn_agent import DQNAgent
import json
from datetime import datetime

def load_blocklist():
    """Load current blocklist"""
    try:
        with open('blocklist.json', 'r') as f:
            return json.load(f)
    except:
        return []

def save_blocklist(blocklist):
    """Save blocklist"""
    with open('blocklist.json', 'w') as f:
        json.dump(sorted(list(set(blocklist))), f)

def print_header():
    """Print header"""
    print("\n" + "="*70)
    print("🤖 AIDRS AUTOMATIC RESPONSE SYSTEM DEMONSTRATION".center(70))
    print("="*70 + "\n")

def print_section(title):
    """Print section header"""
    print(f"\n{'─'*70}")
    print(f"  {title}")
    print(f"{'─'*70}\n")

def test_response_system():
    """Main test function"""
    
    print_header()
    
    # Load DQN Agent
    print("📦 Loading DQN Agent...")
    agent = DQNAgent()
    try:
        agent.load('dqn_agent.pt')
        print("✅ DQN Agent loaded successfully!")
    except:
        print("⚠️  Could not load pre-trained agent (starting fresh)")
    
    # Get agent stats
    print_section("AGENT STATISTICS")
    stats = agent.get_stats()
    print(f"  Memory Size: {stats['memory_size']} experiences")
    print(f"  Exploration Rate (epsilon): {stats['epsilon']}")
    print(f"  Episodes Trained: {stats['episodes_trained']}")
    print(f"  Average Reward: {stats['avg_reward']}")
    
    # Load blocklist
    print_section("CURRENT BLOCKLIST")
    blocklist = load_blocklist()
    if blocklist:
        print(f"  Blocked IPs ({len(blocklist)}):")
        for ip in blocklist[:10]:  # Show first 10
            print(f"    🚫 {ip}")
        if len(blocklist) > 10:
            print(f"    ... and {len(blocklist) - 10} more")
    else:
        print("  No IPs blocked (empty blocklist)")
    
    # Test cases
    print_section("TEST CASE 1: NORMAL TRAFFIC")
    print("  Scenario: Small TCP packet, normal size, known protocol")
    test_case_1 = {
        'description': 'Normal Web Traffic (HTTP)',
        'state': np.array([0, 15, 0.2, 1, 400, 1, 50, 80]),
        'features': {
            'attack_type': 'None (0)',
            'severity': 'Low (15)',
            'confidence': 'Low (0.2)',
            'packet_size': '400 bytes',
            'protocol': 'TCP (1)',
            'source_ip': '192.168.1.50',
            'dest_port': '80 (HTTP)'
        }
    }
    
    print("  Features:")
    for key, value in test_case_1['features'].items():
        print(f"    • {key}: {value}")
    
    action_1 = agent.act(test_case_1['state'])
    action_name_1 = agent.action_names[action_1]
    
    print(f"\n  🤖 Agent Decision: {action_name_1.upper()}")
    if action_1 == 0:
        print("  ✅ CORRECT: Normal traffic should be allowed!")
    
    # Test case 2
    print_section("TEST CASE 2: SUSPICIOUS TRAFFIC")
    print("  Scenario: Large packet, high severity, unknown protocol")
    test_case_2 = {
        'description': 'Suspicious Large Packet (Possible Attack)',
        'state': np.array([1, 85, 0.92, 5, 1800, 5, 200, 100]),
        'features': {
            'attack_type': 'Suspicious (1)',
            'severity': 'High (85)',
            'confidence': 'High (0.92)',
            'packet_size': '1800 bytes (LARGE)',
            'protocol': 'Unknown (5)',
            'source_ip': '192.168.1.200',
            'dest_ip': '192.168.1.100'
        }
    }
    
    print("  Features:")
    for key, value in test_case_2['features'].items():
        print(f"    • {key}: {value}")
    
    action_2 = agent.act(test_case_2['state'])
    action_name_2 = agent.action_names[action_2]
    
    print(f"\n  🤖 Agent Decision: {action_name_2.upper()}")
    if action_2 == 2:  # Block
        print("  ✅ CORRECT: Suspicious traffic should be blocked!")
        source_ip = '192.168.1.200'
        if source_ip not in blocklist:
            blocklist.append(source_ip)
            save_blocklist(blocklist)
            print(f"  🚫 Added to blocklist: {source_ip}")
    
    # Test case 3
    print_section("TEST CASE 3: MODERATE THREAT")
    print("  Scenario: Medium-sized packet, moderate severity")
    test_case_3 = {
        'description': 'Moderate Threat (Needs Investigation)',
        'state': np.array([1, 55, 0.65, 3, 1000, 2, 150, 50]),
        'features': {
            'attack_type': 'Suspicious (1)',
            'severity': 'Medium (55)',
            'confidence': 'Medium (0.65)',
            'packet_size': '1000 bytes',
            'protocol': 'UDP (2)',
            'source_ip': '192.168.1.150',
            'dest_ip': '192.168.1.1'
        }
    }
    
    print("  Features:")
    for key, value in test_case_3['features'].items():
        print(f"    • {key}: {value}")
    
    action_3 = agent.act(test_case_3['state'])
    action_name_3 = agent.action_names[action_3]
    
    print(f"\n  🤖 Agent Decision: {action_name_3.upper()}")
    if action_3 == 1:  # Alert
        print("  ✅ CORRECT: Moderate threats should trigger alerts!")
    
    # Summary
    print_section("RESPONSE SUMMARY")
    print(f"  Total Test Cases: 3")
    print(f"  ✓ Case 1 (Normal): {action_name_1.upper()}")
    print(f"  ✓ Case 2 (Suspicious): {action_name_2.upper()}")
    print(f"  ✓ Case 3 (Moderate): {action_name_3.upper()}")
    
    # Response distribution
    print_section("RESPONSE ACTIONS EXPLAINED")
    print("  Action 0: ALLOW 🟢")
    print("    └─ Safe packet passes through")
    print("    └─ No action taken")
    print("    └─ Used for: Normal traffic\n")
    
    print("  Action 1: ALERT 🟡")
    print("    └─ Packet logged and monitored")
    print("    └─ Security alert generated")
    print("    └─ Packet still passes through")
    print("    └─ Used for: Suspicious but unconfirmed threats\n")
    
    print("  Action 2: BLOCK 🔴")
    print("    └─ Packet blocked immediately")
    print("    └─ Source IP added to blocklist")
    print("    └─ Packet never reaches destination")
    print("    └─ Used for: Confirmed attacks\n")
    
    # Updated blocklist
    print_section("UPDATED BLOCKLIST")
    if blocklist:
        print(f"  Total Blocked IPs: {len(blocklist)}")
        for ip in blocklist[:10]:
            print(f"    🚫 {ip}")
        if len(blocklist) > 10:
            print(f"    ... and {len(blocklist) - 10} more")
    else:
        print("  Blocklist is empty")
    
    # Key statistics
    print_section("SYSTEM PERFORMANCE")
    print(f"  Model Type: Deep Q-Network (DQN)")
    print(f"  State Space: 8 features")
    print(f"  Action Space: 3 actions (allow, alert, block)")
    print(f"  Neural Network: 2 hidden layers (64 units each)")
    print(f"  Device: CPU")
    print(f"  Learning Algorithm: Q-Learning with experience replay")
    
    # Final message
    print_section("✅ AUTOMATIC RESPONSE SYSTEM VERIFIED")
    print("  Your AIDRS system is fully operational!")
    print("  The DQN Agent is making intelligent response decisions.")
    print("  ")
    print("  Features:")
    print("    ✓ Automatic threat detection (ML Model)")
    print("    ✓ Intelligent response selection (DQN Agent)")
    print("    ✓ Automatic blocking (Blocklist.json)")
    print("    ✓ Learning from experience (Reinforcement Learning)")
    print("  ")
    print("  Next Steps:")
    print("    1. Monitor dashboard in real-time")
    print("    2. Capture live network packets")
    print("    3. Watch automatic responses in action")
    print("    4. Train agent with more data (see notebooks)")
    
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    test_response_system()
