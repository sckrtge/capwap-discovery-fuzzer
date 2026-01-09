sudo /home/gxm/projects/.venv/bin/python -m capwap_discovery_fuzzer \
  --pcap ./pcaps/sample_discovery_request.pcap \
  --ac-ip 192.168.10.128 \
  --ac-port 5246 \
  --rounds 20 \
  --timeout 0.1
