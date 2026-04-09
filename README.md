# CAPWAP Discovery Fuzzer

> 本项目为**重庆大学本科毕业设计**《针对CAPWAP协议的安全分析工具设计与实现》的项目代码。
>
> This repository contains the source code for the undergraduate thesis project *"Design and Implementation of a Security Analysis Tool for the CAPWAP Protocol"* at Chongqing University.

---

A fuzzing tool for CAPWAP (Control And Provisioning of Wireless Access Points) Discovery Requests over UDP port 5246. It sends structurally mutated discovery packets to a target Access Controller (AC) and classifies responses as valid, timeout, or error — logging every request/response pair as JSON for later replay and crash reproduction.

针对 CAPWAP（无线接入点控制与配置协议）Discovery Request 报文的模糊测试工具，工作在 UDP 5246 端口。向目标 AC（接入控制器）发送结构变异的探测包，将响应分类为 valid（有效）、timeout（超时）或 error（错误），并将每对请求/响应记录为 JSON 文件，支持后续复现和崩溃分析。

---

## Features / 功能特性

- **Unicast and broadcast modes** — target a specific AC IP or send to `255.255.255.255`
  **单播与广播模式** — 指定目标 AC IP 或向 `255.255.255.255` 广播
- **Structured mutations** — fuzz CAPWAP/Control headers, message element types/lengths/values, flags, element ordering
  **结构化变异** — 对 CAPWAP/Control 头部、消息元素类型/长度/值、标志位、元素顺序进行模糊测试
- **Byte-level mutations** — random overwrites, insertions, deletions, shuffles, segment duplication/reversal
  **字节级变异** — 随机覆写、插入、删除、乱序、片段复制/反转
- **Chained mutations** — each round applies 1–3 structured mutations followed by 0–3 byte-level mutations
  **链式变异** — 每轮依次施加 1–3 次结构化变异和 0–3 次字节级变异
- **Reproducible runs** — seed-controlled RNG; all results written to JSON
  **可复现运行** — 种子控制随机数；所有结果写入 JSON
- **Replay mode** — re-send saved request logs for crash reproduction
  **重放模式** — 重发已保存的请求日志以复现崩溃
- **PCAP import** — load a captured Discovery Request as the base packet
  **PCAP 导入** — 从抓包文件加载 Discovery Request 作为基础报文
- **Crash detection** — periodically probe the target with a valid packet; save `crash_report.json` and exit with code 2 on no response
  **崩溃检测** — 周期性发送合法探测包；目标无响应时保存 `crash_report.json` 并以退出码 2 退出

---

## Requirements / 环境要求

- Python >= 3.10

---

## Installation / 安装

```bash
# Clone the repository / 克隆仓库
git clone https://github.com/sckrt/capwap_discovery_fuzzer.git
cd capwap-discovery-fuzzer

# Install dependencies / 安装依赖
pip install -e .

# Install with dev/test dependencies / 安装开发/测试依赖
pip install -e ".[test]"
```

---

## Usage / 使用方法

### Unicast mode (target a specific AC) / 单播模式（指定目标 AC）

```bash
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --rounds 100 \
  --timeout 3 \
  --iface lo
```

### Broadcast mode / 广播模式

```bash
sudo python -m capwap_discovery_fuzzer \
  --broadcast \
  --ac-port 5246 \
  --rounds 100 \
  --timeout 3 \
  --iface eth0
```

### Load a base packet from PCAP / 从 PCAP 加载基础报文

```bash
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --pcap ./capture.pcap \
  --rounds 50
```

### Replay saved logs for crash reproduction / 重放日志以复现崩溃

```bash
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --replay-json-dir ./capwap_log/20240101_120000/responses/
```

### All options / 全部参数

| Option | Default | Description / 说明 |
|--------|---------|-------------|
| `--ac-ip` | — | Target AC IP address (unicast; required unless `--broadcast`) / 目标 AC IP（单播模式，与 `--broadcast` 二选一） |
| `--broadcast` | `false` | Send to `255.255.255.255` / 向全网段广播 |
| `--ac-port` | `5246` | Target UDP port / 目标 UDP 端口 |
| `--rounds` | `1` | Number of fuzzing iterations / 模糊测试轮数 |
| `--timeout` | `3.0` | Seconds to wait for a response per round / 每轮响应等待超时（秒） |
| `--sleep` | `1.0` | Sleep between rounds (seconds) / 每轮间隔（秒） |
| `--seed` | random | RNG seed for reproducible runs / 随机数种子，用于复现运行 |
| `--pcap` | — | PCAP file containing one CAPWAP Discovery Request / 含 Discovery Request 的 PCAP 文件 |
| `--replay-json-dir` | — | Directory of JSON logs to replay instead of fuzzing / 待重放的 JSON 日志目录 |
| `--iface` | `lo` | Network interface / 网络接口 |
| `--probe-interval` | `10` | Check target liveness every N rounds; 0 = disabled. Exits with code 2 and saves `crash_report.json` on crash / 每 N 轮探测目标存活；0 为禁用；崩溃时退出码为 2 并保存 `crash_report.json` |

---

## Output / 输出结构

Each run creates a timestamped directory under `./capwap_log/`:

每次运行在 `./capwap_log/` 下创建带时间戳的目录：

```
capwap_log/
└── 20240101_120000/
    ├── fuzzer.log
    ├── crash_report.json        # 仅崩溃检测触发时生成 / only on crash detection
    └── responses/
        ├── response_20240101_120001_000001.json
        └── ...
```

Each JSON file contains the full request (hex + parsed structure), the raw response, the response classification, and the mutation chain that produced the packet — enough information to reproduce any interesting finding.

每个 JSON 文件包含完整请求（十六进制 + 解析结构）、原始响应、响应分类及产生该报文的变异链，信息足以复现任何值得关注的发现。

Response types / 响应类型：

| Type / 类型 | Meaning / 含义 |
|------|---------|
| `valid` | AC returned a well-formed Discovery Response (MsgType=2, required elements present) / AC 返回了合法的 Discovery Response |
| `timeout` | No response received within the timeout window / 超时未收到响应 |
| `error` | Response received but failed structural validation / 收到响应但结构校验失败 |

---

## Development / 开发

```bash
pytest                        # run tests / 运行测试
pytest -k "pattern"           # run tests matching pattern / 运行匹配的测试
coverage run -m pytest && coverage html  # coverage report (HTML) / 生成覆盖率报告
pip install build && python -m build     # build the package / 构建包
```

---

## License / 许可证

MIT
