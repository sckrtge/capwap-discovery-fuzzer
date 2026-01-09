sudo /home/gxm/projects/.venv/bin/python -m capwap_discovery_fuzzer \
  --broadcast \
  --ac-port 5246 \
  --rounds 200 \
  --timeout 3 \
  --pcap ./pcaps/sample_discovery_request.pcap \
