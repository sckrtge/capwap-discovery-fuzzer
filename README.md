# CAPWAP Discovery Fuzzer

> 本项目为**重庆大学本科毕业设计**《针对CAPWAP协议的安全分析工具设计与实现》的项目代码。
>
> This repository contains the source code for the undergraduate thesis project *"Design and Implementation of a Security Analysis Tool for the CAPWAP Protocol"* at Chongqing University.

---

A fuzzing tool for CAPWAP (Control And Provisioning of Wireless Access Points) Discovery Requests over UDP port 5246. It sends structurally mutated discovery packets to a target Access Controller (AC), classifies responses as valid / timeout / error, and logs every round to a structured JSONL file for analysis, replay, and crash reproduction.

针对 CAPWAP（无线接入点控制与配置协议）Discovery Request 报文的模糊测试工具，工作在 UDP 5246 端口。向目标 AC（接入控制器）发送结构变异的探测包，将响应分类为 valid / timeout / error，并将每轮结果追加到结构化 JSONL 日志，支持后续数据分析、定向重放和崩溃复现。

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
- **Reproducible runs** — seed-controlled RNG; every result written to `records.jsonl`
  **可复现运行** — 种子控制随机数；所有结果写入 `records.jsonl`
- **Structured JSONL logging** — one record per round with round number, timestamp, method chain, response type, hex payload, and elapsed time; load directly with `pandas` for analysis and charting
  **结构化 JSONL 日志** — 每轮一条记录，含轮次、时间戳、变异链、响应类型、十六进制载荷、耗时；可直接用 `pandas` 加载分析作图
- **Session summary** — `summary.json` written at end of run: total stats, per-method effectiveness, response time percentiles
  **会话汇总** — 运行结束写入 `summary.json`：总计统计、各方法有效性、响应时间百分位
- **Filtered replay** — re-send records from `records.jsonl` for crash reproduction; filter by `response_type` (e.g. only replay `error` records)
  **过滤重放** — 从 `records.jsonl` 定向重放；支持按 `response_type` 过滤（如只重放 `error`）
- **PCAP import** — load a captured Discovery Request as the base packet
  **PCAP 导入** — 从抓包文件加载 Discovery Request 作为基础报文
- **Crash detection** — periodically probe the target with a valid packet; save `crash_report.json` and exit with code 2 on no response
  **崩溃检测** — 周期性发送合法探测包；目标无响应时保存 `crash_report.json` 并以退出码 2 退出
- **Vendor extension** — `--vendor cisco` activates Cisco C9800 WLC mode: authentic AP discovery packet structure, accepts MsgType=2/20, extracts Cisco VSP fields
  **厂商扩展** — `--vendor cisco` 启用 Cisco C9800 WLC 模式：使用真实 AP 报文结构，接受 MsgType=2/20，提取 Cisco VSP 字段

---

## Requirements / 环境要求

- Python >= 3.10
- [scapy](https://scapy.net/) — packet crafting and parsing / 报文构造与解析
- [typer](https://typer.tiangolo.com/) — CLI framework / 命令行框架
- [rich](https://github.com/Textualize/rich) — terminal progress bar and tables / 终端进度条与表格（typer 依赖自动安装）

All runtime dependencies are declared in `pyproject.toml` and installed automatically via `pip install -e .`

所有运行时依赖已在 `pyproject.toml` 中声明，执行 `pip install -e .` 自动安装。

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

### Unicast mode / 单播模式

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

### Cisco C9800 WLC mode / Cisco C9800 模式

```bash
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.10.201 \
  --rounds 100 --timeout 5 --iface ens37 \
  --vendor cisco
```

### Replay saved records for crash reproduction / 重放日志以复现崩溃

```bash
# Replay all records / 重放全部记录
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --replay-jsonl ./capwap_log/20240101_120000/records.jsonl

# Replay only error records / 只重放 error 记录
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --replay-jsonl ./capwap_log/20240101_120000/records.jsonl \
  --replay-filter error
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
| `--replay-jsonl` | — | `records.jsonl` file to replay instead of fuzzing / 待重放的 JSONL 文件（替代 fuzzing 模式） |
| `--replay-filter` | — | Filter records by `response_type` when replaying, e.g. `error` / 重放时按 `response_type` 过滤 |
| `--iface` | `lo` | Network interface / 网络接口 |
| `--probe-interval` | `10` | Check target liveness every N rounds; 0 = disabled. Exits with code 2 and saves `crash_report.json` on crash / 每 N 轮探测目标存活；0 为禁用；崩溃时退出码为 2 并保存 `crash_report.json` |
| `--vendor` | — | Vendor-specific mode, e.g. `cisco` for Cisco C9800 WLC / 厂商模式，如 `cisco` |

---

## Output / 输出结构

Each run creates a timestamped directory under `./capwap_log/`:

每次运行在 `./capwap_log/` 下创建带时间戳的目录：

```
capwap_log/
└── 20240101_120000/
    ├── fuzzer.log          # 运行日志 / runtime log
    ├── session.json        # 会话参数 / session parameters
    ├── records.jsonl       # 每轮一行 / one record per round
    ├── summary.json        # 汇总统计 / aggregated statistics
    └── crash_report.json   # 仅崩溃检测触发时 / only on crash detection
```

### records.jsonl

One JSON object per line:

```json
{
  "round": 42,
  "timestamp": "2024-01-01T12:00:05.123456",
  "method_chain": ["fuzz_capwap_header", "brutal_random_bytes"],
  "response_type": "error",
  "error_type": "MissingControlHeaderError",
  "request_hex": "...",
  "response_hex": "...",
  "elapsed_ms": 312
}
```

Load all records with pandas for analysis and charting:

```python
import pandas as pd
df = pd.read_json("capwap_log/20240101_120000/records.jsonl", lines=True)
df["response_type"].value_counts().plot.pie()
```

### summary.json

Written at end of run. Includes total counts, per-method effectiveness (how often each mutation method triggered an error), and response time statistics:

```json
{
  "total": 100, "valid": 23, "timeout": 15, "error": 62,
  "error_types": {"MissingControlHeaderError": 40},
  "method_effectiveness": {
    "fuzz_capwap_header": {"uses": 35, "valid": 5, "timeout": 2, "error": 28}
  },
  "response_time_stats": {"mean_ms": 312, "min_ms": 50, "max_ms": 980, "p95_ms": 750}
}
```

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
