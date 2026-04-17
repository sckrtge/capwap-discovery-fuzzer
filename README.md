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
- **Structured mutations** — 21 named methods covering CAPWAP/Control header fields, all message element TLV fields, element structure operations, and flag combinations
  **结构化变异** — 21 个具名方法，覆盖 CAPWAP/Control 头部字段、消息元素 TLV 字段、元素结构操作及标志位组合
- **Byte-level mutations** — 10 methods: random overwrites, bit flips, insertions, deletions, segment zero-fill/repeat-fill, duplication, reversal, shuffle, and truncation
  **字节级变异** — 10 个方法：随机覆写、位翻转、插入、删除、区间清零/填充、片段复制/反转、全字节乱序、截断
- **Chained mutation strategy** — structured mutations first (Scapy-parseable), byte-level after; `brutal_shuffle_bytes` forced to chain end
  **链式变异策略** — 结构化变异在前，字节级在后；`brutal_shuffle_bytes` 强制为链末步骤
- **Reproducible runs** — seed-controlled RNG; every result written to `records.jsonl`
  **可复现运行** — 种子控制随机数；所有结果写入 `records.jsonl`
- **Structured JSONL logging** — one record per round with round number, timestamp, method chain, response type, hex payload, and elapsed time
  **结构化 JSONL 日志** — 每轮一条记录，含轮次、时间戳、变异链、响应类型、十六进制载荷、耗时
- **Session summary** — `summary.json` written at end: total stats, per-method effectiveness, response time percentiles, crash info
  **会话汇总** — 运行结束写入 `summary.json`：总计统计、各方法有效性、响应时间百分位、崩溃信息
- **Filtered replay** — re-send records from `records.jsonl` for crash reproduction; filter by `response_type`
  **过滤重放** — 从 `records.jsonl` 定向重放；支持按 `response_type` 过滤
- **Crash detection** — periodically probe the target; save `crash_report.json` + `crash_sequence.jsonl` and exit code 2 on no response
  **崩溃检测** — 周期性发送合法探测包；目标无响应时保存 `crash_report.json` + `crash_sequence.jsonl` 并以退出码 2 退出
- **Gray-box mode (OpenCAPWAP)** — `--vendor opencapwap` (default): auto-detects AC process via `pgrep`, runs background process monitor sampling `/proc/<pid>/status` every second, distinguishes Crash vs DoS via three-state liveness check
  **灰盒模式（OpenCAPWAP）** — `--vendor opencapwap`（默认）：自动 `pgrep AC` 获取 PID，后台线程每秒采样 `/proc/<pid>/status` 写 `process_monitor.csv`，三态检测区分 Crash 与 DoS
- **Vendor extension** — `--vendor cisco` activates Cisco C9800 WLC mode: authentic AP discovery packet structure, accepts MsgType=2/20, extracts Cisco VSP fields
  **厂商扩展** — `--vendor cisco` 启用 Cisco C9800 WLC 模式：真实 AP 报文结构，接受 MsgType=2/20，提取 Cisco VSP 字段
- **Analysis tools** — `tools/analyze_results.py` (single session charts) and `tools/compare_sessions.py` (multi-session comparison)
  **分析脚本** — `tools/analyze_results.py`（单会话图表）和 `tools/compare_sessions.py`（多会话对比）

---

## Requirements / 环境要求

- Python >= 3.10
- [scapy](https://scapy.net/) — packet crafting and parsing / 报文构造与解析
- [typer](https://typer.tiangolo.com/) — CLI framework / 命令行框架
- [rich](https://github.com/Textualize/rich) — terminal progress bar and tables / 终端进度条与表格

All runtime dependencies are declared in `pyproject.toml` and installed automatically via `pip install -e .`

所有运行时依赖已在 `pyproject.toml` 中声明，执行 `pip install -e .` 自动安装。

---

## Installation / 安装

```bash
git clone https://github.com/sckrtge/capwap-discovery-fuzzer.git
cd capwap-discovery-fuzzer
pip install -e .

# With dev/test dependencies / 含开发测试依赖
pip install -e ".[test]"
```

---

## Usage / 使用方法

### OpenCAPWAP gray-box mode (default) / OpenCAPWAP 灰盒模式（默认）

```bash
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --rounds 500 --timeout 3 --sleep 0.5 \
  --iface lo \
  --probe-interval 10 --on-probe-fail continue \
  --vendor opencapwap
```

### Unicast mode / 单播模式

```bash
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --rounds 100 --timeout 3 --iface lo
```

### Broadcast mode / 广播模式

```bash
sudo python -m capwap_discovery_fuzzer \
  --broadcast --ac-port 5246 \
  --rounds 100 --timeout 3 --iface eth0
```

### Cisco C9800 WLC mode / Cisco C9800 模式

```bash
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.10.201 \
  --rounds 200 --timeout 2 --sleep 0.1 \
  --iface ens37 \
  --probe-interval 10 --on-probe-fail stop \
  --vendor cisco
```

### Replay for crash reproduction / 重放崩溃序列

```bash
# Replay crash_sequence.jsonl / 重放崩溃前驱序列
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --vendor opencapwap \
  --replay-jsonl ./capwap_log/20260415_165736/crash_sequence.jsonl

# Replay only error records / 只重放 error 记录
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --replay-jsonl ./capwap_log/20260415_165736/records.jsonl \
  --replay-filter error
```

### Analysis tools / 分析脚本

```bash
# Single session charts / 单会话图表
python tools/analyze_results.py capwap_log/<timestamp>/

# Multi-session comparison / 多会话对比
python tools/compare_sessions.py capwap_log/ --vendor opencapwap
```

### All CLI options / 全部参数

| Option | Default | Description / 说明 |
|--------|---------|-------------------|
| `--ac-ip` | — | Target AC IP (unicast; required unless `--broadcast`) / 目标 AC IP |
| `--broadcast` | `false` | Send to `255.255.255.255` / 广播模式 |
| `--ac-port` | `5246` | Target UDP port / 目标 UDP 端口 |
| `--rounds` | `1` | Fuzzing iterations / 模糊测试轮数 |
| `--timeout` | `3.0` | Response timeout per round (s) / 每轮超时（秒） |
| `--sleep` | `1.0` | Sleep between rounds (s) / 每轮间隔（秒） |
| `--seed` | random | RNG seed / 随机数种子 |
| `--pcap` | — | Base packet from PCAP file / 从 PCAP 加载基础报文 |
| `--replay-jsonl` | — | Replay mode: path to `records.jsonl` / 重放模式：JSONL 文件路径 |
| `--replay-filter` | — | Filter by `response_type` when replaying / 重放过滤字段 |
| `--iface` | `lo` | Network interface / 网络接口 |
| `--probe-interval` | `10` | Liveness check every N rounds; 0 = disabled / 每 N 轮存活探测 |
| `--on-probe-fail` | `continue` | `continue` (record DoS) or `stop` (halt immediately) / 探测失败行为 |
| `--vendor` | `opencapwap` | `opencapwap` (gray-box), `cisco` (C9800), `generic` (black-box) / 厂商模式 |

---

## Fuzzing Strategy / 变异策略

Each round constructs one mutated packet. The mutation pipeline has two sequential stages:

每轮构造一个变异报文，变异流水线分两个顺序阶段：

```
base_pkt ──► [structured mutations]* ──► [byte-level mutations]* ──► send
```

**Stage 1 — Structured mutations**: selected by `random.choices` (repetition allowed), sorted by layer dependency order.

**Stage 2 — Byte-level mutations**: 75% of rounds include ≥1 byte-level mutation; `brutal_shuffle_bytes` is always the final step.

---

## Output / 输出结构

```
capwap_log/20240101_120000/
├── fuzzer.log              # 运行日志
├── session.json            # 会话参数（seed、target、vendor、rounds 等）
├── records.jsonl           # 每轮一行 NDJSON
├── summary.json            # 汇总统计 + 方法有效性 + 响应时间分位
├── process_monitor.csv     # 【灰盒独有】进程内存/CPU 时序（每秒）
├── suspected_event.json    # 【DoS 事件】探测失败但进程存活时写入
├── crash_report.json       # 【崩溃事件】进程死亡时写入
└── crash_sequence.jsonl    # 【崩溃事件】崩溃前 50 条记录
```

### records.jsonl

```json
{
  "round": 42,
  "timestamp": "2024-01-01T12:00:05.123456",
  "method_chain": ["fuzz_capwap_wbid", "brutal_bitflip"],
  "response_type": "timeout",
  "error_type": "NoResponseError",
  "request_hex": "...",
  "response_hex": "",
  "elapsed_ms": 3001
}
```

| `response_type` | Meaning / 含义 |
|-----------------|----------------|
| `valid` | Well-formed Discovery Response received / 收到合法 Discovery Response |
| `timeout` | No response within timeout / 超时无响应 |
| `error` | Response failed structural validation / 响应结构校验失败 |

---

## Project Structure / 项目结构

```
src/capwap_discovery_fuzzer/
├── cli.py                        # Typer CLI 入口
├── capwap_discovery_fuzzer.py    # 核心 Fuzzer 类
├── payload_fuzzer.py             # 31 个变异方法（21 safe + 10 brutal）
├── request_creater.py            # Scapy 报文类 + Payload_Creator
├── response_parser.py            # 响应解析与分类
├── errors.py                     # 异常层级
└── vendors/
    ├── __init__.py               # get_vendor() 工厂函数
    ├── base.py                   # VendorFuzzer 抽象基类
    ├── opencapwap/
    │   └── fuzzer.py             # 灰盒扩展（进程监控 + 三态检测）
    └── cisco/
        ├── creator.py            # CiscoPayloadCreator
        ├── elements.py           # Cisco 常量 + 真实抓包 raw bytes
        ├── fuzzer.py             # CiscoCAPWAPDiscoveryFuzzer
        └── response_parser.py    # CiscoResponseParser

tools/
├── analyze_results.py            # 单会话图表（5种）
└── compare_sessions.py           # 多会话对比图表（6种）

experiments/
├── opencapwap/experiment_report.md   # OpenCAPWAP 实验报告（含根因分析）
└── cisco/experiment_report.md        # Cisco C9800 实验报告

thesis_materials/                 # 论文写作素材（报告、图表、数据）
```

---

## Experiment Results / 实验结果

### OpenCAPWAP Gray-box (2026-04-15) / OpenCAPWAP 灰盒测试

3 independent sessions, 500 rounds each. 3 vulnerabilities confirmed and reproduced.

3次独立实验（各500轮），确认并复现3个漏洞：

| Vuln | Type / 类型 | Root Cause / 根因 | Reproduced / 复现 |
|------|-------------|-------------------|:-----------------:|
| VULN-01 | DoS — WTP slot exhaustion | `ACMainLoop.c:373`: resource allocation before validation / 资源分配在验证之前 | ✅ |
| VULN-02 | SIGSEGV — NULL SSL session | `CWSecurity.c:302`: `SSL_read(NULL)` when `pBuffer[0]&0xf==1` / 首字节误判为 DTLS 包 | ✅ |
| VULN-03 | Same as VULN-02, triggered in 10 rounds | High-efficiency path via `brutal_shuffle_bytes` / 字节乱序高效触发 | ✅ |

Full report: [`experiments/opencapwap/experiment_report.md`](experiments/opencapwap/experiment_report.md)

### Cisco C9800 Black-box (2026-04-17) / Cisco C9800 黑盒测试

3 independent sessions × 200 rounds. No crash or DoS detected.

3次独立实验（各200轮），无崩溃，无DoS：

| Metric | Value |
|--------|-------|
| Valid rate / valid 率 | ~7% |
| Core filter condition / 核心过滤条件 | MsgType=19 AND MsgElemsLen=231 |
| RFC deviations (low severity) / 协议合规偏差（低危） | T-bit, Fragment bits, WBID not validated |

Full report: [`experiments/cisco/experiment_report.md`](experiments/cisco/experiment_report.md)

---

## Development / 开发

```bash
pytest                                       # run tests
pytest -k "pattern"                          # run tests matching pattern
coverage run -m pytest && coverage html      # coverage report
```

---

## License / 许可证

MIT
