# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Git

Always commit with the default identity **sckrtge** (`2962886557@qq.com`). This is already configured as the repo's `user.name`/`user.email` — do not change it.

## Project

重庆大学本科毕业设计《针对CAPWAP协议的安全分析工具设计与实现》项目代码。

## Commands

This project uses standard Python tooling.

```bash
# Install dependencies
pip install -e .
pip install -e ".[test]"

# Run tests
pytest
pytest -k "pattern"

# Coverage
coverage run -m pytest && coverage html
```

## Architecture

The tool fuzzes CAPWAP (Control And Provisioning of Wireless Access Points) Discovery Requests over UDP port 5246 and classifies AC responses.

**Data flow:**
1. `cli.py` — Typer CLI entry point, handles `--ac-ip`/`--broadcast`/`--pcap`/`--replay-json-dir`/`--iface`/`--probe-interval`/`--vendor` options, drives fuzzing rounds
2. `capwap_discovery_fuzzer.py` — `CAPWAPDiscoveryFuzzer` orchestrates: creates/loads base packet, applies mutations, sends via Python native `socket` (UDP), classifies responses, appends one JSONL record per round to `./capwap_log/<timestamp>/records.jsonl`; writes `session.json` at startup and `summary.json` at end
3. `request_creater.py` — Scapy packet class definitions (`CAPWAP_Header`, `Control_Header`, `MessageElement`, `WTPDescriptor`, etc.) + `Payload_Creator` for constructing valid or random discovery requests + `parse_discovery_request()` for loading from pcap
4. `payload_fuzzer.py` — `Payload_Fuzzer` wraps a base packet; provides 21 structured "safe" fuzz methods (CAPWAP/Control header fields, element TLV fields, element structural ops) and 10 "brutal" raw-byte methods (overwrite, bitflip, insert, delete, zero/fill segment, duplicate, reverse, truncate, shuffle); all methods carry bilingual (EN/ZH) docstrings
5. `response_parser.py` — `ResponseParser` parses raw response bytes using Scapy, classifies as `valid`/`error`/`timeout`/`unknown`, raises typed errors from `errors.py`
6. `errors.py` — Exception hierarchy: `CAPWAPFuzzerError` → `NoResponseError`, `InvalidResponseError` → `MissingCapwapHeaderError`, `MissingControlHeaderError`, `UnexpectedMsgTypeError`, `MissingRequiredElementError`, etc.; `CrashDetectedError`

**Fuzzing strategy** (`CAPWAPDiscoveryFuzzer.fuzzing`): see *Fuzzing Strategy (2026-04-15)* section below for full details. In short: each round sends 1 packet (`MUTATION_COUNT=1`). Stage 1 picks 1–`max_safe_methods` structured methods via `random.choices` (repeats allowed), sorts them by layer dependency order, then applies them in sequence. Stage 2 picks 0–`max_brutal_methods` byte-level methods (75 % chance of ≥1); `brutal_shuffle_bytes` is forced to the end of the chain. Results are bucketed as valid/timeout/error and written to `records.jsonl`.

**Replay mode**: `--replay-jsonl` replays records from `records.jsonl` against the target — useful for crash reproduction. `--replay-filter error` limits replay to records of a specific `response_type`.

**Scapy layer binding**: `request_creater.py` and `response_parser.py` temporarily `bind_layers` / `split_layers` around parsing to avoid global state pollution.

## Running the fuzzer

```bash
# Unicast mode targeting local AC
sudo bash run_fuzzing.sh

# Broadcast mode
sudo bash run_fuzzing_broadcast.sh

# Manual invocation — unicast
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --rounds 10 \
  --timeout 3 \
  --iface lo

# Manual invocation — broadcast
sudo python -m capwap_discovery_fuzzer \
  --broadcast \
  --ac-port 5246 \
  --rounds 10 \
  --timeout 3 \
  --iface lo

# Cisco C9800 mode
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.10.201 \
  --rounds 10 --timeout 5 --iface ens37 \
  --vendor cisco

# Replay saved JSONL for crash reproduction
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --replay-jsonl ./capwap_log/20240101_120000/records.jsonl

# Only replay error records
sudo python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.33.128 \
  --replay-jsonl ./capwap_log/20240101_120000/records.jsonl \
  --replay-filter error
```

Does NOT require root privileges (uses Python native UDP socket, not raw socket).

## Pre-flight Check (2026-04-09)

Before the fuzzing loop starts, `cli.py` calls `is_target_alive()` once. If all retries fail, the program prints an error and exits with **code 1** (`Target AC ... is not reachable or not running. Aborting.`). This prevents wasted fuzzing rounds against an unreachable target.

## Crash Detection (2026-04-09)

Crash detection is designed for OpenCAPWAP grey-box testing and is extensible for commercial targets.

**How it works:**
- `--probe-interval N` (default 10, 0 = disabled): every N rounds, `CAPWAPDiscoveryFuzzer.is_target_alive()` is called before the next fuzzing round begins.
- `is_target_alive()` sends a valid `Payload_Creator.create_discovery_request(valid=True)` probe and waits for any UDP response, retrying up to 3 times. Returns `True` if any attempt gets a response.
- If all retries fail, `CrashDetectedError` is raised (defined in `errors.py`), the fuzzing loop stops, `crash_report.json` is written to the current log directory, and the process exits with **code 2**.

**`crash_report.json` fields:** `crash_detected_at_round`, `probe_attempts`, `ac_ip`, `ac_port`, `timestamp`, `total_status`.

**Extension point:** `is_target_alive()` is designed to be overridden. Subclasses targeting commercial ACs (e.g. vSmartZone) can override this method to use alternative liveness strategies (ICMP ping, vendor-specific keepalive, HTTP health check) without modifying the base fuzzer logic.

## Key findings & fixes (2026-04-07)

### Bugs fixed
1. **Broadcast destination was `None`** — Fixed: use `"255.255.255.255"` when `broadcast=True`.
2. **Brutal mutation methods ignored their `pkt` argument** — Fixed: operate directly on `pkt`.
3. **Safe mutation methods didn't chain** — Fixed: all safe methods accept optional `pkt` parameter and clone from it when provided.
4. **`ResponseParser._bind_layers()` called in `__init__`** — Fixed: removed from `__init__`, only bind/unbind inside `parse_response`.
5. **Double `logging.basicConfig`** — Fixed: `basicConfig` called once in CLI after fuzzer is created.
6. **Scapy `sr1` cannot reach local IP** — Fixed: replaced Scapy send/receive with Python native `socket` (UDP).

### Network topology
- Virtual AC runs as a local process on the same machine, bound to `192.168.33.128:5246` (and `0.0.0.0:5246`).
- `ip route get 192.168.33.128` returns `local ... dev lo` — all traffic to this IP goes through loopback.
- Native UDP socket bypasses ARP/routing issues entirely and reaches the AC correctly.

## Logging

All logging is file-only. After `logging.basicConfig` is called in `cli.py`, non-file handlers are immediately removed so nothing leaks to stderr. All `logging.*` calls in `capwap_discovery_fuzzer.py` use `INFO` or `DEBUG` level — never `WARNING`/`ERROR` directly, to avoid accidental stderr output before the handler is configured.

Do not use extended thinking unless explicitly asked.

---

## 厂商扩展架构 (2026-04-14)

### 设计原则

- 现有所有文件（`request_creater.py` 等）**完全不动**，保持厂商无关性
- 新功能全部写到新文件，通过继承扩展，不破坏现有接口
- `cli.py` 只做最小改动：新增 `--vendor` 选项
- 为未来添加其他厂商（Fortinet、Huawei 等）预留位置

### 目录结构

```
src/capwap_discovery_fuzzer/
├── ... (现有文件完全不动)
├── cli.py                      # 唯一改动：新增 --vendor 选项
│
└── vendors/
    ├── __init__.py             # get_vendor(name) 工厂函数
    ├── base.py                 # VendorFuzzer 抽象基类
    └── cisco/
        ├── __init__.py
        ├── elements.py         # Cisco 常量 + 从真实抓包提取的 raw bytes
        ├── creator.py          # CiscoPayloadCreator(Payload_Creator)
        └── fuzzer.py           # CiscoCAPWAPDiscoveryFuzzer(CAPWAPDiscoveryFuzzer)
```

### 各文件职责

**`vendors/__init__.py`**：`get_vendor(name)` 按名字返回对应 Fuzzer 类，名字不存在返回 `None`（CLI 降级到通用模式）。

**`vendors/base.py`**：`VendorFuzzer` 抽象基类，约定 `create_vendor_discovery_request()` 接口契约，后续新厂商必须继承它。

**`vendors/cisco/elements.py`**：
- 常量：`CISCO_VENDOR_ID = 4232704`（0x40A000）、`RAD_NAME_ELEM_ID = 5`、`BOARD_DATA_OPTIONS_ELEM_ID = 207`
- 从真实 C9800 抓包（`cisco_ap_discovery.json`）提取的 WTP Board Data（Type=38）和 WTP Descriptor（Type=39）的 raw value bytes，确保 C9800 兼容性
- VSP 元素构造辅助函数：`make_vsp(elem_id, data) -> bytes`

**`vendors/cisco/creator.py`**：`CiscoPayloadCreator(Payload_Creator)` 覆盖 `create_discovery_request(valid)`:
- `valid=True`：构造合法 Cisco Discovery Request，包含 M=1 MAC 可选字段（Hlen=4，16 字节头）
  - CAPWAP 头：`CAPWAP_Header(M=1, Hlen=4, WBID=1)` + `Raw(mac_optional_field_8bytes)`
  - 元素顺序（与真实 AP 一致）：Type 20→38→39→41→44→45→28→1048×2→37(VSP207)→37(VSP5)
  - MAC 可选字段作为 `Raw` 层插入，Scapy `getlayer()` 可穿透，所有 safe fuzz 方法仍工作
- `valid=False`：回落到父类随机报文

**`vendors/cisco/fuzzer.py`**：`CiscoCAPWAPDiscoveryFuzzer(CAPWAPDiscoveryFuzzer)` 仅覆盖 `__init__`，将 `self.payload_creator` 替换为 `CiscoPayloadCreator`，`self.response_parser` 替换为 `CiscoResponseParser`。父类其余逻辑全部继承。

**`vendors/cisco/response_parser.py`**：`CiscoResponseParser(ResponseParser)` 针对 C9800 定制：
- 接受 `MsgType=2`（Discovery Response）和 `MsgType=20`（Primary Discovery Response）为 valid（C9800 对部分变异报文回复 MsgType=20）
- 必要元素：`{1, 4, 10}`，AC Name 允许空（Length=0）
- 额外提取 Cisco VSP：ElemID=208（AC Capability）、ElemID=151（Session Token），写入 `parsed_response.cisco` 字段

### CLI 集成

```python
from capwap_discovery_fuzzer.vendors import get_vendor

fuzzer_cls = get_vendor(vendor) if vendor else CAPWAPDiscoveryFuzzer
fuzzer = fuzzer_cls(ac_ip=ac_ip, ...)
```

### Cisco C9800 目标信息

- C9800 WLC IP: `192.168.10.201`（UDP 5246）
- 本机接口: `ens37`（与 C9800 同网段）
- 真实抓包来源：`cisco_ap_discovery.json` + `pcaps/cisco.pcap`（AP 型号 C9105AXI-H）

### Cisco Discovery Request 关键结构（来自真实抓包，已验证 C9800 可响应）

**CAPWAP Header**（16 字节，Hlen=4）：
```
[base 8B: version=0,type=0,Hlen=4,Rid=0,WBID=1,M=1,其余=0]
[optional MAC: 06 10 a8 29 92 61 00 00]  ← Radio MAC + 1-byte pad，共 8 字节
```

**Control Header** 注意事项：
- `MsgType = 0x13`（十进制 19）—— 真实 Cisco AP 使用此值，**不是**标准 RFC 5415 的 Type=1
- `MsgElemsLen` 统计范围（RFC 5415）：从 SeqNum 字段之后开始，即包含 MsgElemsLen(2B) + Flags(1B) + 消息元素区域。因此 `MsgElemsLen = len(elements) + 3`，其中 +3 = MsgElemsLen 字段本身(2B) + Flags(1B)，这是标准行为，非 Cisco 特有

**Vendor Specific Payload 封装格式**（Type=37）：
```
[Type=37, 2B][Length=N+6, 2B][VendorID=4232704, 4B][ElemID, 2B][Data, NB]
```

**元素列表**（顺序与真实 AP 一致）：

| Type | 说明 | Value |
|------|------|-------|
| 20 | Discovery Type | `0x01`（Static Config） |
| 38 | WTP Board Data | VendorID=4232704，raw bytes from capture |
| 39 | WTP Descriptor | MaxRadio=2, RadiosInUse=2, NumEncrypt=0，raw bytes from capture |
| 41 | Frame Tunnel Mode | `0x04` |
| 44 | MAC Type | `0x01`（Split MAC） |
| 45 | WTP Name | `AP10A8.2901.D6B0` |
| 28 | Location Data | `default location` |
| 1048 | 802.11 Radio Info | Radio 0, type=1 |
| 1048 | 802.11 Radio Info | Radio 1, type=2 |
| 37 | VSP ElemID=207 | Board Data Options `01000003` |
| 37 | VSP ElemID=5 | RAD Name `AP10A8.2901.D6B0` |

### 目录结构（最终）

```
vendors/
├── __init__.py
├── base.py
└── cisco/
    ├── __init__.py
    ├── elements.py
    ├── creator.py
    ├── fuzzer.py
    └── response_parser.py
```

### Cisco Discovery Response 结构（来自 pcaps/cisco_ac-ap_1.pcap 分析）

**CAPWAP Header**：Hlen=2（8B），M=0，WBID=0

**Control Header**：MsgType=2（Discovery Response）或 20（Primary Discovery Response）

**元素列表**：

| Type | 说明 | 备注 |
|------|------|------|
| 1 | AC Descriptor | Stations/Limit/ActiveWTPs/MaxRetransmit + Cisco DescriptorSubElem |
| 4 | AC Name | 可为空（Length=0） |
| 10 | AC Name w/ Priority | 含 AC IP（前 4 字节） |
| 1048 | 802.11 Radio Info | |
| 37 | VSP ElemID=208 | AC Capability（1 字节） |
| 37 | VSP ElemID=151 | Session Token（5 字节） |

### Logging Bug Fix (2026-04-14)

**问题**：`fuzzer.log` 未生成。

**根因**：`CAPWAPDiscoveryFuzzer.__init__` 内的 `logging.info()` 调用早于 `cli.py` 里的 `logging.basicConfig()`，触发 Python logging 自动添加 `StreamHandler(stderr)`，导致 `basicConfig` 发现已有 handler 直接跳过，FileHandler 永不创建。

**修复**：在 `cli.py` 调用 `basicConfig` 前执行 `logging.getLogger().handlers.clear()`，强制清除自动添加的 handler。

### 扩展新厂商

在 `vendors/` 下新建子目录（如 `vendors/fortinet/`），实现 `elements.py`、`creator.py`、`fuzzer.py`、`response_parser.py`，在 `vendors/__init__.py` 的 `get_vendor()` 里加一行映射，完全不影响现有代码。

---

## 日志架构重构 (2026-04-14)

### 日志目录结构（最终）

```
capwap_log/20240101_120000/
├── fuzzer.log        # 运行日志（人读，文件独占）
├── session.json      # 会话参数（seed、target、vendor、rounds 等）
├── records.jsonl     # 每轮一行，NDJSON 格式，增量追加
└── summary.json      # 结束时写入：total_status + method_effectiveness + response_time_stats
```

### records.jsonl 字段

每行一个 JSON 对象：

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

- `request_hex`：实际发出的 CAPWAP payload（无 IP/UDP 头），可直接 `sock.sendto(bytes.fromhex(...))` 重放
- `response_hex`：`recvfrom` 返回的完整字节（含 IP/UDP 头），空字符串表示超时

### summary.json 字段

```json
{
  "total": 100, "valid": 23, "timeout": 15, "error": 62,
  "error_types": {"MissingControlHeaderError": 40, ...},
  "method_effectiveness": {
    "fuzz_capwap_header": {"uses": 35, "valid": 5, "timeout": 2, "error": 28}
  },
  "response_time_stats": {
    "mean_ms": 312, "min_ms": 50, "max_ms": 980, "p95_ms": 750
  }
}
```

### API 变更

**`send_discovery_request(discovery_request)`** 返回值从 `(IP_pkt, raw_resp)` 改为 `(capwap_bytes, raw_resp)`：
- `capwap_bytes`：纯 CAPWAP UDP payload（无 IP/UDP 头）
- `raw_resp`：`recvfrom` 原始字节（含 IP/UDP 头），`None` 表示超时

**`classify_discovery_response(capwap_bytes, raw_response, request_info, elapsed_ms)`**：签名从接收 Scapy 包改为接收 bytes，追加到 `records.jsonl` 而非写独立 JSON 文件。

**新方法：**
- `write_session_json(extra=None)`：写 `session.json`，CLI 传入 `extra` 补充 vendor/rounds 等
- `write_summary(total_status)`：读 `records.jsonl` 计算统计，写 `summary.json`
- `replay_request_from_record(record, src_port=None)`：从单条 JSONL 记录重放，使用原生 socket（修复原 `sr1` bug）
- `replay_requests_from_jsonl(jsonl_path, filter_fn=None, src_port=None)`：批量重放，`filter_fn` 支持任意字段过滤

**已删除：**
- `_scapy_to_json()`
- `replay_request_from_json()`（原用 `sr1`，有 loopback 收包 bug）
- `replay_requests_from_dir()`

### CLI 变更

- `--replay-json-dir`（目录）→ `--replay-jsonl`（文件，指向 `records.jsonl`）
- 新增 `--replay-filter <response_type>`：按 `response_type` 过滤重放，如 `--replay-filter error`
- Replay 模式不再套 rounds 循环，直接一次性重放整个 JSONL 文件

---

## Fuzzing Strategy (2026-04-15)

### payload_fuzzer.py 重构

**方法重命名**：原 `fuzz_any_msg_*` / `fuzz_specific_msg` / `fuzz_duplicate_msg` / `fuzz_drop_last_msg` / `fuzz_shuffle_msgs` 等命名中 "msg" 语义不清，无法从日志直接判断操作对象，全部重命名为 `fuzz_elem_*` / `fuzz_ctrl_*` 前缀规范：

| 旧名 | 新名 |
|------|------|
| `fuzz_control_header` | 拆分为 `fuzz_ctrl_msgtype` / `fuzz_ctrl_seqnum` / `fuzz_ctrl_msgelemslen` / `fuzz_ctrl_flags` |
| `fuzz_any_msg_type` | `fuzz_elem_type` |
| `fuzz_any_msg_length` | `fuzz_elem_length` |
| `fuzz_any_msg_value` | `fuzz_elem_value` |
| `fuzz_specific_msg` | `fuzz_elem_value_by_type` |
| `fuzz_duplicate_msg` | `fuzz_elem_duplicate` |
| `fuzz_drop_last_msg` | `fuzz_elem_drop`（逻辑改为随机删任意元素） |
| `fuzz_shuffle_msgs` | `fuzz_elem_order_shuffle` |
| `brutal_duplicate_segments` | `brutal_duplicate_segment` |

**新增结构化方法（9 个）**：`fuzz_capwap_wbid`、`fuzz_capwap_fragment`、`fuzz_ctrl_msgtype`、`fuzz_ctrl_seqnum`、`fuzz_ctrl_flags`、`fuzz_elem_length_zero`、`fuzz_elem_length_overflow`、`fuzz_elem_insert_unknown`、`fuzz_elem_drop_required`

**新增字节级方法（4 个）**：`brutal_bitflip`、`brutal_zero_segment`、`brutal_fill_segment`、`brutal_truncate`

所有方法添加中英文双语 docstring，说明变异目标字段和预期触发行为。

### fuzzing 策略改进（CAPWAPDiscoveryFuzzer.fuzzing）

**核心约束**：brutal 方法破坏 Scapy 层结构，safe 方法依赖 `getlayer()` 解析，因此执行顺序只能是 safe → brutal，不可颠倒。

**改进点：**

1. **safe 改用 `random.choices`（允许重复）**：原 `random.sample` 保证无重复，导致 `fuzz_elem_value` 等方法无法在同一轮内变异多个元素。改为 `choices` 后，同一方法可被多次选中，叠加覆盖不同元素。

2. **sort_key 精化**：`fuzz_elem_insert_unknown` 单独排在 level 3，`fuzz_elem_order_shuffle` 排 level 4，强制 insert 先于 shuffle，使新插入的未知元素参与乱序。

3. **`brutal_shuffle_bytes` 强制为 brutal 链末尾**：全字节乱序后任何 brutal 方法均无额外价值。若 shuffle 被选中，前置 brutal 方法仍正常执行，shuffle 强制追加为最后一步。

4. **brutal 下界调整**：75% 概率 brutal 下界为 1（至少一次字节级变异），25% 概率为 0（纯结构化轮次，用于协议合规性测试）。原 `randint(0, 3)` 有 25% 的轮次完全无 brutal 变异，比例偏高。

---

## 实验数据与 OpenCAPWAP 灰盒扩展计划 (2026-04-15)

### 背景

实验目标：
- **OpenCAPWAP AC**（灰盒）：本地进程，可直接访问 `/proc/<pid>`，已观察到两个可稳定复现的异常（见"已知异常现象"节）
- **Cisco C9800 WLC**（黑盒）：只能通过 UDP 回包判断存活，`--vendor cisco` 模式不变

### 新增文件输出

```
capwap_log/20240101_120000/
├── fuzzer.log
├── session.json
├── records.jsonl
├── summary.json              # 增强：新增 crash_at_round / top_crash_methods / response_time_trend
├── process_monitor.csv       # 【灰盒独有】进程健康指标时序（每秒采样）
├── suspected_event.json
├── crash_report.json
└── crash_sequence.jsonl      # 【新】崩溃前 50 条记录，自动从 records.jsonl 提取
```

#### `process_monitor.csv` 字段

| 字段 | 说明 |
|------|------|
| `timestamp` | ISO 时间戳 |
| `round` | 当前 fuzzing 轮次 |
| `pid_alive` | `True/False`（`kill -0 <pid>`） |
| `vmrss_kb` | 物理内存（`/proc/<pid>/status` VmRSS） |
| `vmvirt_kb` | 虚拟内存（VmSize） |
| `cpu_percent` | CPU 占用（两次读 `/proc/<pid>/stat` 差值） |

#### `summary.json` 增强字段

```json
{
  "crash_detected": true,
  "crash_at_round": 342,
  "dos_suspected": false,
  "top_crash_methods": ["fuzz_elem_length_overflow", "brutal_truncate"],
  "response_time_trend": {
    "first_50_rounds_mean_ms": 45,
    "last_50_rounds_mean_ms": 312
  }
}
```

### OpenCAPWAP 灰盒扩展架构

#### 目录结构

```
vendors/
├── __init__.py          # "opencapwap" → OpenCAPWAPFuzzer；"opencapwap" 为默认 vendor
├── base.py
├── cisco/               # 完全不动
└── opencapwap/
    ├── __init__.py
    └── fuzzer.py        # OpenCAPWAPFuzzer
```

#### `vendors/__init__.py` 变更

- `get_vendor("opencapwap")` → `OpenCAPWAPFuzzer`
- `get_vendor("cisco")` → `CiscoCAPWAPDiscoveryFuzzer`
- `get_vendor("generic")` → `CAPWAPDiscoveryFuzzer`（显式黑盒模式）
- `--vendor` CLI 默认值从 `None` 改为 `"opencapwap"`

#### `OpenCAPWAPFuzzer` 设计

继承 `CAPWAPDiscoveryFuzzer`，覆盖两处：

**`__init__`**：自动 `pgrep AC` 获取 PID。
- 找到 → 灰盒模式，启动进程监控侧车线程
- 未找到 → 警告，降级为纯 UDP 模式（等同基类）

**`is_target_alive()`**：双重检测。
```
kill -0 <pid>
  → 进程消失        → return False（确认 Crash）
  → 进程存在 + 无UDP回包 → return False（疑似死锁/DoS）
  → 进程存在 + 有UDP回包 → return True（正常）
```
比基类多了"进程活着但不响应"的第三态区分。

**进程监控侧车**：后台 `threading.Thread`，每秒采样 `/proc/<pid>/status` 和 `/proc/<pid>/stat`，写 `process_monitor.csv`。通过共享 `self._current_round`（`fuzzing()` 每轮更新）关联轮次。线程在 `fuzzing()` 结束后自动停止。

### `crash_sequence.jsonl` 提取时机

在 `cli.py` 写 `crash_report.json` 的同一位置，调用 `fuzzer.write_crash_sequence(last_n=50)`，该方法读取 `records.jsonl` 尾部 50 行写入 `crash_sequence.jsonl`。

### `summary.json` 增强时机

`write_summary()` 内部计算，新增：
- `crash_at_round`：从 `crash_report.json` 读（若存在）
- `top_crash_methods`：从 `crash_sequence.jsonl` 的 method_chain 统计频次（若存在）
- `response_time_trend`：比较 records 前 50 条和后 50 条的 elapsed_ms 均值

### 分析脚本

放在 `tools/` 目录，实验结束后独立运行，不影响 fuzzer 主体：

| 脚本 | 功能 | 产出 |
|------|------|------|
| `tools/analyze_results.py` | 读单个 log 目录 | 响应类型饼图、方法有效性柱状图、响应时间折线图、内存趋势折线图（灰盒）、错误类型分布条形图 |
| `tools/compare_sessions.py` | 读多个 log 目录 | 多 session MTTC 对比、响应类型分布对比、不同 vendor 结果对比 |

### 已知异常现象（待源码根因分析）

**现象一：AP 计数异常（DoS）**
持续发送畸形 Discovery Request 时，`gActiveWTPs` 持续递增至 `gMaxWTPs`，导致合法 AP 无法接入。正常 Discovery 阶段不应触发 WTP 计数。根因疑似在 `ACDiscoveryState.c` 或 `ACProtocol.c` 的计数逻辑位置错误。

**现象二：累积性 Crash**
持续发送变异报文约 100–500 条后 AC 进程必然崩溃，可稳定复现，单条不可独立触发。疑似内存泄漏或越界写，每条畸形包泄漏少量内存，累积后触发。根因疑似在报文解析或状态管理代码中。

**注**：源码根因分析待实验数据收集完成后进行。

### 实施顺序（已全部完成，2026-04-15）

1. ✅ `vendors/opencapwap/fuzzer.py`（PID 自动检测 + 进程监控侧车 + `is_target_alive()` 覆盖）
2. ✅ `vendors/__init__.py`：新增 opencapwap 映射，默认 vendor 改为 opencapwap
3. ✅ `cli.py`：`--vendor` 默认值改为 `"opencapwap"`，接入监控生命周期
4. ✅ `capwap_discovery_fuzzer.py`：新增 `write_crash_sequence()`，`write_summary()` 增强
5. ✅ `tools/analyze_results.py`
6. ✅ `tools/compare_sessions.py`

---

## 当前完整目录结构（2026-04-15）

```
src/capwap_discovery_fuzzer/
├── __main__.py
├── capwap_discovery_fuzzer.py   # 主 Fuzzer 类
├── cli.py                       # Typer CLI 入口
├── errors.py                    # 异常层级
├── payload_fuzzer.py            # 21 个 safe + 10 个 brutal 变异方法
├── request_creater.py           # Scapy 报文类 + Payload_Creator
├── response_parser.py           # 响应解析与分类
├── utils.py
└── vendors/
    ├── __init__.py              # get_vendor() + DEFAULT_VENDOR="opencapwap"
    ├── base.py
    ├── cisco/
    │   ├── creator.py           # CiscoPayloadCreator
    │   ├── elements.py          # Cisco 常量 + raw bytes
    │   ├── fuzzer.py            # CiscoCAPWAPDiscoveryFuzzer
    │   └── response_parser.py   # CiscoResponseParser
    └── opencapwap/
        ├── __init__.py
        └── fuzzer.py            # OpenCAPWAPFuzzer（灰盒）

tools/
├── analyze_results.py           # 单会话分析 + 5 张图表
└── compare_sessions.py          # 多会话对比 + 6 张图表/CSV

run_fuzzing_opencapwap.sh        # 一键启动 AC + fuzzing 复合脚本
```

---

## 实验流程（毕设标准流程）

### 环境说明

- OpenCAPWAP AC 目录：`/home/gxm/projects/openCAPWAP-ubuntu2404/`
- AC 监听地址：`192.168.33.128:5246`（loopback 可达）
- Python venv：`/home/gxm/projects/.venv/bin/python`
- sudo 密码：`123123`

### 第一阶段：正式模糊测试（建议 3 次独立实验）

每次实验前 AC 进程必须重新启动（保证状态干净）：

```bash
# 方式一：一键脚本（推荐）
bash run_fuzzing_opencapwap.sh
```

或手动：

```bash
# 1. 启动 AC
cd /home/gxm/projects/openCAPWAP-ubuntu2404
echo "123123" | sudo -S killall -9 AC 2>/dev/null || true
sleep 1
echo "123123" | sudo -S ./AC . &>/tmp/opencapwap_ac.log &
sleep 3

# 2. 启动 fuzzer（回到 fuzzer 目录）
cd /home/gxm/projects/fuzzing/capwap-discovery-fuzzer
echo "123123" | sudo -S /home/gxm/projects/.venv/bin/python -m capwap_discovery_fuzzer \
    --ac-ip 192.168.33.128 \
    --rounds 500 \
    --timeout 3 \
    --sleep 0.5 \
    --iface lo \
    --probe-interval 10 \
    --on-probe-fail continue \
    --vendor opencapwap
```

建议每次使用不同 `--seed` 或不传（自动随机），确保 3 次实验独立。

### 第二阶段：生成单会话图表

```bash
# 替换为实际时间戳
/home/gxm/projects/.venv/bin/python tools/analyze_results.py \
    capwap_log/<timestamp>/

# 图表输出到 ./charts/<timestamp>/
# 包含：响应类型饼图、方法有效性柱状图、响应时间折线图、
#       内存趋势折线图、CPU 折线图（如有 process_monitor.csv）
```

### 第三阶段：多会话对比

```bash
# 对比所有 opencapwap 会话
/home/gxm/projects/.venv/bin/python tools/compare_sessions.py \
    capwap_log/ --vendor opencapwap

# 输出到 ./charts/compare_Nsessions/
# 包含：session_overview、mttc_comparison、method_heatmap、
#       memory_overlay、response_time_overlay、sessions_table.csv
```

### 第四阶段：崩溃复现

```bash
# 重启 AC
cd /home/gxm/projects/openCAPWAP-ubuntu2404
echo "123123" | sudo -S ./AC . &>/tmp/opencapwap_ac.log &
sleep 3

# 用崩溃前驱序列重放
cd /home/gxm/projects/fuzzing/capwap-discovery-fuzzer
echo "123123" | sudo -S /home/gxm/projects/.venv/bin/python -m capwap_discovery_fuzzer \
    --ac-ip 192.168.33.128 \
    --vendor opencapwap \
    --replay-jsonl capwap_log/<crash_session>/crash_sequence.jsonl
```

### 第五阶段：源码根因分析（实验数据收集完成后）

目标文件（OpenCAPWAP 源码）：
- `ACDiscoveryState.c` — Discovery 状态机，现象一计数逻辑
- `ACProtocol.c` / `CWProtocol.c` — 报文解析，现象二内存问题
- `CWAC.h` — `gActiveWTPs` / `gMaxWTPs` 全局变量定义

分析要点：
1. 现象一：`gActiveWTPs++` 在 Discovery 阶段何时被调用，是否在合法性检查之前
2. 现象二：`malloc`/`realloc` 是否有对应 `free`，报文解析路径上是否存在提前返回导致内存未释放

### 关键输出文件说明

| 文件 | 论文用途 |
|------|------|
| `process_monitor.csv` | 内存泄漏趋势图（最核心的漏洞证据） |
| `summary.json` `.method_effectiveness` | 变异方法有效性分析表 |
| `crash_sequence.jsonl` | 崩溃触发序列，用于复现实验章节 |
| `suspected_event.json` | DoS 事件时间点记录 |
| `charts/*/method_heatmap.png` | 多会话方法有效性热力图 |
| `charts/*/mttc_comparison.png` | MTTC 可重复性验证图 |
| `charts/*/process_memory.png` | 内存增长曲线（含崩溃标记线） |

---

## 实验进展（2026-04-15）

### 已完成

**阶段一～三（数据收集 + 图表）：已全部完成。**

3 次独立 OpenCAPWAP 灰盒实验已跑完，结果写入 `experiments/opencapwap/experiment_report.md`。

| 会话 ID | 轮次 | 崩溃轮次 | DoS 事件 | 内存增长 |
|---------|------|---------|---------|---------|
| 20260415_165736 | 89 | 第90轮（Segfault） | 第20轮触发，第70轮恢复 | +1188 KB |
| 20260415_170825 | 10 | 第10轮（Segfault） | 无 | +104 KB |
| 20260415_170915 | 494 | 未崩溃 | 第30轮触发，第180轮恢复 | +1640 KB |

**已确认漏洞（3个）：**

| 漏洞 | 类型 | 描述 |
|------|------|------|
| VULN-01 | DoS | 畸形 Discovery Request 导致 `gActiveWTPs` 耗尽（100% 复现） |
| VULN-02 | 累积性 Crash | 持续发包内存泄漏，约 90 轮后 Segfault |
| VULN-03 | 极早直接 Crash | 特定方法组合 10 轮内即触发 Segfault |

**代码修复（同步提交）：**
- `records.jsonl` 轮次编号全为 1 的 bug（`round_number` 参数链路）
- `continue` 模式无法区分 DoS 和 Crash 的逻辑（新增 `is_process_alive()`）
- `_raw_to_pkt` 暴力变异后不再重新解析，改为 `Raw(bytes(raw))` 避免 struct.unpack 异常

### 下一步：漏洞复现（阶段四）

目标：对三个漏洞分别设计定向复现实验，验证可重复触发，并为论文提供复现章节的证据。

#### VULN-01 复现（DoS）

通过 `replay-jsonl` 重放会话1的前 30 条记录（DoS 触发前驱），观察 AC 日志中 "Too many WTPs" 是否重现：

```bash
cd /home/gxm/projects/openCAPWAP-ubuntu2404
echo "123123" | sudo -S killall -9 AC 2>/dev/null || true; sleep 1
echo "123123" | sudo -S ./AC . &>/tmp/opencapwap_ac.log &
sleep 3

cd /home/gxm/projects/fuzzing/capwap-discovery-fuzzer
echo "123123" | sudo -S /home/gxm/projects/.venv/bin/python -m capwap_discovery_fuzzer \
    --ac-ip 192.168.33.128 --vendor opencapwap \
    --replay-jsonl capwap_log/20260415_165736/crash_sequence.jsonl
```

判断标准：`grep "Too many WTPs" /tmp/opencapwap_ac.log`

#### VULN-02/03 复现（Crash）

重放对应 crash_sequence.jsonl，观察 AC 进程是否再次 Segfault：

```bash
# VULN-02（会话1）
echo "123123" | sudo -S /home/gxm/projects/.venv/bin/python -m capwap_discovery_fuzzer \
    --ac-ip 192.168.33.128 --vendor opencapwap \
    --replay-jsonl capwap_log/20260415_165736/crash_sequence.jsonl

# VULN-03（会话2）
echo "123123" | sudo -S /home/gxm/projects/.venv/bin/python -m capwap_discovery_fuzzer \
    --ac-ip 192.168.33.128 --vendor opencapwap \
    --replay-jsonl capwap_log/20260415_170825/crash_sequence.jsonl
```

判断标准：shell 报告 `段错误`，`process_monitor.csv` 中 `pid_alive` 变为 False。

#### 注意事项

- 复现前必须重启 AC（`killall -9 AC`）
- 复现结果记录到 `experiments/opencapwap/experiment_report.md` 第7节
- 复现成功后进入**阶段五（源码根因分析）**
