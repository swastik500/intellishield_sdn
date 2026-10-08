#!/bin/bash
echo "=== Phase 7 Local Math/Logic Unit Tests ==="
python3 verify_phase7.py
echo ""
echo "=== How to Test Phase 7 Live on VM ==="
echo "Terminal 1 (VM):"
echo "  cd ~/intellishield-sdn"
echo "  osken-manager controller/flow_monitor.py"
echo ""
echo "Terminal 2 (VM):"
echo "  sudo mn --topo single,3 --mac --switch ovsk --controller remote"
echo "  mininet> h1 ping h2 -c 10"
echo "  mininet> h1 hping3 -S --flood -p 80 10.0.0.2"
