#!/bin/bash
# run_fuzzing_opencapwap.sh
# 启动 OpenCAPWAP AC 并对其进行灰盒模糊测试。
# Launch OpenCAPWAP AC and run gray-box fuzzing against it.

set -e

AC_DIR="/home/gxm/projects/openCAPWAP-ubuntu2404"
PYTHON="/home/gxm/projects/.venv/bin/python"

AC_IP="192.168.33.128"
IFACE="lo"
ROUNDS=500
TIMEOUT=3
SLEEP=0.5
PROBE_INTERVAL=10

# ---------- 1. 清理旧 AC 进程 ----------
echo "[*] Killing any existing AC process..."
echo "123123" | sudo -S killall -9 AC 2>/dev/null || true
sleep 1

# ---------- 2. 启动 AC（后台） ----------
echo "[*] Starting OpenCAPWAP AC in background..."
cd "$AC_DIR"
echo "123123" | sudo -S ./AC . &>/tmp/opencapwap_ac.log &
AC_BGPID=$!
echo "[+] AC launched (shell PID: $AC_BGPID)"

# 等待 AC 完成初始化并开始监听 UDP 5246
echo "[*] Waiting for AC to initialise (3s)..."
sleep 3

# 验证 AC 进程确实在运行
AC_PID=$(pgrep -x AC || true)
if [ -z "$AC_PID" ]; then
    echo "[!] AC process not found after startup — aborting."
    exit 1
fi
echo "[+] AC process running (PID: $AC_PID)"

# ---------- 3. 回到 fuzzer 目录并启动 fuzzing ----------
cd /home/gxm/projects/fuzzing/capwap-discovery-fuzzer

echo "[*] Starting fuzzer (vendor=opencapwap, rounds=$ROUNDS)..."
echo "123123" | sudo -S "$PYTHON" -m capwap_discovery_fuzzer \
    --ac-ip "$AC_IP" \
    --rounds "$ROUNDS" \
    --timeout "$TIMEOUT" \
    --sleep "$SLEEP" \
    --iface "$IFACE" \
    --probe-interval "$PROBE_INTERVAL" \
    --on-probe-fail continue \
    --vendor opencapwap

echo "[+] Fuzzing complete."
