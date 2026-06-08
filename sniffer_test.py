"""
AIDRS Sniffer Test - Captures packets without requiring full ML model
Useful for testing and generating training data
"""

import csv
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from datetime import datetime
import sys
import json

print("="*70)
print("🛡️ AIDRS Sniffer Test Mode")
print("="*70)

# Get available interfaces
if_list = get_if_list()
print(f"\n🌐 Available Network Interfaces:")
for i, iface in enumerate(if_list, 1):
    print(f"   {i}. {iface}")

# Select interface
print(f"\n💡 Tip: Use WiFi interface or first non-loopback interface")
iface = if_list[3] if len(if_list) > 3 else (if_list[0] if if_list else None)

if not iface:
    print("❌ No network interfaces found!")
    sys.exit(1)

print(f"✅ Selected interface: {iface}")

# Output file
project_root = Path(__file__).parent
csv_file = project_root / "live_events_test.csv"

print(f"📁 Output file: {csv_file}")

# Write header
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp", "src_ip", "dst_ip", "protocol", 
        "length", "summary", "verdict", "confidence"
    ])

print(f"\n🔴 Starting packet capture (Ctrl+C to stop)...\n")

packet_count = 0

def log_packet(pkt):
    global packet_count
    packet_count += 1
    
    if IP not in pkt:
        return
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    # Determine protocol
    if TCP in pkt:
        proto = "TCP"
    elif UDP in pkt:
        proto = "UDP"
    elif ICMP in pkt:
        proto = "ICMP"
    else:
        proto = str(pkt[IP].proto)
    
    # Simple rule-based verdict
    length = len(pkt)
    if length > 1500:
        verdict = "Suspicious"
        confidence = "0.70"
    else:
        verdict = "Benign"
        confidence = "0.95"
    
    # Log to CSV
    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip,
            dst_ip,
            proto,
            length,
            pkt.summary()[:80],
            verdict,
            confidence
        ])
    
    # Print to console
    emoji = "✅" if verdict == "Benign" else "⚠️"
    print(f"{emoji} [{packet_count:4d}] {src_ip:15} → {dst_ip:15} | {proto:4} | {length:5} bytes | {verdict}")

try:
    sniff(
        iface=iface,
        filter="ip",
        prn=log_packet,
        store=False,
        count=0  # Capture indefinitely
    )
except PermissionError:
    print("\n❌ Permission denied. Run as Administrator:")
    print("   Right-click PowerShell/CMD → Run as Administrator")
    print("   Then run: python sniffer_test.py")
except KeyboardInterrupt:
    print(f"\n\n⏹️  Capture stopped by user")
except Exception as e:
    print(f"\n❌ Error: {type(e).__name__}: {e}")
    if "Npcap" in str(e) or "WinPcap" in str(e):
        print("   Npcap not found. Install from: https://npcap.com/")

print(f"\n{'='*70}")
print(f"📊 Captured {packet_count} packets")
print(f"💾 Saved to: {csv_file}")
print(f"{'='*70}")

print(f"\n🚀 Next Steps:")
print(f"   1. Train IDS model with this data:")
print(f"      python aidrs_config.py train-ids --data {csv_file}")
print(f"   2. Run dashboard:")
print(f"      streamlit run dashboard_enhanced.py")
