#!/usr/bin/env python3
"""
最简 CAPWAP Discovery Request 重放脚本
从 pcap 提取第一个 UDP payload，原样发送到目标，等待回包。
用法: sudo python3 replay.py
"""

import socket
import struct
import sys

PCAP_FILE = "./pcaps/cisco.pcap"
TARGET_IP = "192.168.10.201"
TARGET_PORT = 5246
TIMEOUT = 3  # 秒


def read_first_udp_payload(pcap_path: str) -> bytes:
    with open(pcap_path, "rb") as f:
        # pcap global header (24 bytes)
        magic = struct.unpack_from("<I", f.read(4))[0]
        assert magic == 0xA1B2C3D4, "不支持的 pcap 格式（仅支持小端 pcap）"
        f.read(20)  # 跳过剩余 global header

        # 读第一个包
        pkt_hdr = f.read(16)
        if len(pkt_hdr) < 16:
            raise ValueError("pcap 文件为空")
        cap_len = struct.unpack_from("<I", pkt_hdr, 8)[0]
        raw = f.read(cap_len)

    # 解析 Ethernet(14) + IP(可变) + UDP(8) -> payload
    eth_type = struct.unpack_from(">H", raw, 12)[0]
    assert eth_type == 0x0800, f"非 IPv4 帧: 0x{eth_type:04x}"
    ihl = (raw[14] & 0x0F) * 4
    proto = raw[14 + 9]
    assert proto == 17, f"非 UDP 协议: {proto}"
    udp_start = 14 + ihl
    payload = raw[udp_start + 8:]
    return payload


def main():
    try:
        payload = read_first_udp_payload(PCAP_FILE)
    except Exception as e:
        print(f"[ERROR] 读取 pcap 失败: {e}")
        sys.exit(1)

    print(f"[*] 已读取 payload，长度 {len(payload)} 字节")
    print(f"[*] 前 16 字节: {payload[:16].hex()}")
    print(f"[*] 目标: {TARGET_IP}:{TARGET_PORT}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        sock.sendto(payload, (TARGET_IP, TARGET_PORT))
        print(f"[+] 已发送，等待回包（{TIMEOUT}s）...")
        data, addr = sock.recvfrom(4096)
        print(f"[+] 收到回包！来自 {addr}，长度 {len(data)} 字节")
        print(f"    前 16 字节: {data[:16].hex()}")
    except socket.timeout:
        print("[-] 超时，未收到回包")
    except PermissionError:
        print("[ERROR] 需要 root 权限，请用 sudo 运行")
    finally:
        sock.close()


if __name__ == "__main__":
    main()