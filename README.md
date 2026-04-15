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
- **Structured mutations** — 21 named methods covering CAPWAP/Control header fields, all message element TLV fields, element structure operations, and flag combinations; each method targets a specific protocol field so logs are directly interpretable
  **结构化变异** — 21 个具名方法，覆盖 CAPWAP/Control 头部字段、消息元素 TLV 字段、元素结构操作及标志位组合；每个方法针对特定协议字段，日志可直接判断变异位置
- **Byte-level mutations** — 10 methods: random overwrites, bit flips, insertions, deletions, segment zero-fill/repeat-fill, duplication, reversal, shuffle, and truncation
  **字节级变异** — 10 个方法：随机覆写、位翻转、插入、删除、区间清零/填充、片段复制/反转、全字节乱序、截断
- **Chained mutation strategy** — structured mutations first (Scapy-parseable), byte-level after (structure destroyed); allows repeated method selection for multi-element coverage; `brutal_shuffle_bytes` forced to chain end
  **链式变异策略** — 结构化变异在前（Scapy 可解析），字节级在后（结构已破坏）；允许重复选取方法实现多元素覆盖；`brutal_shuffle_bytes` 强制为链末步骤
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

## Fuzzing Strategy / 变异策略

Each fuzzing round constructs one mutated packet and sends it to the target AC.  The mutation pipeline has two sequential stages — structured mutations must complete before byte-level mutations begin, because byte-level operations destroy the Scapy layer structure that structured methods depend on.

每轮 fuzzing 构造一个变异报文发送给目标 AC。变异流水线分两个顺序阶段——结构化变异必须在字节级变异之前完成，因为字节级操作会破坏结构化方法所依赖的 Scapy 层结构。

```
base_pkt ──► [structured mutations]* ──► [byte-level mutations]* ──► send
```

### Stage 1 — Structured mutations / 第一阶段：结构化变异

Methods are selected by `random.choices` (repetition allowed) so the same method can be applied multiple times in one round (e.g. `fuzz_elem_value` can corrupt two different elements).  The selected methods are then sorted into a fixed execution order to respect field dependencies:

方法通过 `random.choices`（允许重复）选取，同一方法可在一轮内多次应用（如 `fuzz_elem_value` 可在同一轮内破坏两个不同元素）。选出的方法按固定顺序执行以保证字段依赖关系：

| Order / 顺序 | Group / 分组 | Methods / 方法 |
|:---:|---|---|
| 1 | CAPWAP Header fields | `fuzz_capwap_header`, `fuzz_capwap_wbid`, `fuzz_capwap_flags`, `fuzz_capwap_fragment` |
| 2 | Control Header fields | `fuzz_ctrl_msgtype`, `fuzz_ctrl_seqnum`, `fuzz_ctrl_msgelemslen`, `fuzz_ctrl_flags` |
| 3 | Element field mutations | `fuzz_elem_type`, `fuzz_elem_length`, `fuzz_elem_length_zero`, `fuzz_elem_length_overflow`, `fuzz_elem_value`, `fuzz_elem_value_by_type(38)`, `fuzz_elem_value_by_type(39)` |
| 4 | Element insert | `fuzz_elem_insert_unknown` |
| 5 | Element structure | `fuzz_elem_drop`, `fuzz_elem_drop_required`, `fuzz_elem_duplicate`, `fuzz_elem_order_shuffle` |

Ordering rationale / 排序理由：
- CAPWAP Header first because `Hlen` determines the offset of every subsequent layer.
  CAPWAP 头部最先，因为 `Hlen` 决定后续所有层的偏移量。
- Insert before shuffle so newly inserted unknown elements also participate in reordering.
  Insert 先于 shuffle，使新插入的未知元素也参与乱序。

### Stage 2 — Byte-level mutations / 第二阶段：字节级变异

Selected by `random.choices` (repetition allowed).  75% of rounds include at least one byte-level mutation; 25% are structured-only (useful for protocol compliance testing).

通过 `random.choices`（允许重复）选取。75% 的轮次至少包含一次字节级变异；25% 为纯结构化轮次（用于协议合规性测试）。

| Method / 方法 | What it does / 操作说明 |
|---|---|
| `brutal_random_bytes` | Overwrite ~10% of bytes at random positions / 随机位置覆写约 10% 的字节 |
| `brutal_bitflip` | XOR 1–8 random bytes with a single-bit mask / 对 1–8 个随机字节做单比特 XOR 翻转 |
| `brutal_insert_random_bytes` | Insert 1–5 bursts of random bytes / 插入 1–5 段随机字节 |
| `brutal_delete_random_bytes` | Delete 1–5 individual bytes / 删除 1–5 个字节 |
| `brutal_zero_segment` | Zero-fill a random contiguous segment / 随机区间清零 |
| `brutal_fill_segment` | Fill a random segment with a repeated byte (0xFF, 0xAA…) / 随机区间填充单一字节值 |
| `brutal_duplicate_segment` | Copy a segment and insert it elsewhere / 复制一段字节并插入到随机位置 |
| `brutal_reverse_segment` | Reverse byte order of a random segment / 反转随机区间的字节顺序 |
| `brutal_truncate` | Drop all bytes after a random cut point / 从随机偏移处截断报文 |
| `brutal_shuffle_bytes` | Shuffle ALL bytes (terminal — always last) / 全字节乱序（终结步，强制为链末） |

`brutal_shuffle_bytes` is **always the last step** in the byte-level chain.  If it is selected alongside other brutal methods, the others execute first; shuffle executes last.  Any method after a full shuffle would have no additional effect.

`brutal_shuffle_bytes` **始终是字节级链的最后一步**。若与其他 brutal 方法同时被选中，其他方法先执行，shuffle 最后执行。全字节乱序后再执行任何方法均无额外效果。

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
