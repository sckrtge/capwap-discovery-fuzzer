
### Basic fuzzing run

```bash
# run in ./capwap_discovery_fuzzer
python -m capwap_discovery_fuzzer \
  --pcap ./pcaps/sample_discovery_request.pcap \
  --ac-ip 192.168.10.128 \
  --ac-port 5246 \
  --rounds 1 \
  --seed 1337
```
