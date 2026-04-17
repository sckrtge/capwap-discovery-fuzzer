# Cisco C9800 WLC 模糊测试实验报告

**项目**：针对 CAPWAP 协议的安全分析工具设计与实现  
**目标**：Cisco Catalyst 9800 WLC（商用无线控制器）  
**测试类型**：黑盒模糊测试（纯 UDP 响应分类，无进程级监控）  
**实验日期**：2026-04-17  
**测试人员**：gxm  

---

## 1. 实验环境

| 项目 | 值 |
|------|----|
| 测试主机 | Ubuntu 24.04，网卡 `ens37` |
| 目标设备 | Cisco Catalyst 9800 WLC |
| 目标地址 | `192.168.10.201:5246`（UDP） |
| 网络路径 | 同网段直连（RTT < 1ms） |
| Fuzzer | capwap-discovery-fuzzer（本仓库 main 分支） |
| Python | `/home/gxm/projects/.venv/bin/python` |
| 运行权限 | `sudo`（UDP socket 绑定） |

### Fuzzer 参数（标准配置）

```
--ac-ip 192.168.10.201
--rounds 200
--timeout 2
--sleep 0.1
--iface ens37
--probe-interval 10
--on-probe-fail stop
--vendor cisco
```

### 与 OpenCAPWAP 灰盒测试的关键差异

| 维度 | OpenCAPWAP（灰盒） | Cisco C9800（黑盒） |
|------|-------------------|-------------------|
| 崩溃检测 | `kill -0 <pid>` + UDP 双重 | 纯 UDP 响应检测 |
| 进程监控 | `/proc/<pid>` 内存/CPU 采样 | 不可用，无 `process_monitor.csv` |
| 崩溃/DoS 区分 | 三态（正常/DoS/Crash） | 仅能观测"停止响应" |
| 目标重启成本 | 本地 `killall -9 AC` | 硬件重启，影响更大 |
| Vendor 模式 | `--vendor opencapwap` | `--vendor cisco` |

---

## 2. 实验目标

1. **验证工具链兼容性**：确认 `CiscoCAPWAPDiscoveryFuzzer` 能与真实 C9800 正常交互，pre-flight 探测通过。
2. **基线行为采集**：记录 C9800 对各类变异报文的响应类型分布（valid/timeout/error）。
3. **异常输入验收分析**：分析哪些不合法报文被 C9800 接受，识别 C9800 输入验证的宽松点。
4. **稳定性观测**：判断持续发送畸形包是否引发响应时间退化、持续 timeout 窗口（DoS 信号）或 probe 失败（崩溃信号）。

---

## 3. 实验方法

### 3.1 连通性验证（第0阶段）

正式实验前执行 20 轮验证测试（`run_fuzzing_cisco.sh`），确认：
- C9800 pre-flight 探测通过
- 工具链完整（`CiscoPayloadCreator` → UDP socket → `CiscoResponseParser`）
- 至少存在 valid 响应（验证 Cisco Discovery Request 构造正确）

### 3.2 正式测试流程

进行 3 次独立实验，每次使用不同随机 seed（自动生成），参数固定：

1. Pre-flight check：向目标发送合法探测包，失败则中止
2. 每轮选取 1~N 个 safe 方法 + 0~3 个 brutal 方法，顺序应用于基础 Cisco Discovery Request
3. 发送变异包，等待 UDP 响应（timeout=2s）
4. 每 10 轮执行 probe 存活检测；失败则停止并写 `crash_report.json`
5. 结束后写 `summary.json`

### 3.3 valid/timeout 判断逻辑

`CiscoResponseParser` 接受以下条件为 `valid`：

- MsgType = 2（Discovery Response）或 20（Primary Discovery Response）
- 必要元素 Type `{1, 4, 10}` 均存在
- AC Name（Type=4）允许 Length=0

所有其他情况分类为 `error` 或 `timeout`（无响应）。

### 3.4 valid 报文分析方法

对全部 valid 记录使用 Scapy 字段级解码（非手工 bit 计算），逐字段统计 CAPWAP Header（Version/Hlen/WBID/T/F/L/W/M/K）和 Control Header（MsgType/SeqNum/MsgElemsLen/Flags），识别哪些字段偏离协议规范仍被 C9800 接受。

---

## 4. 实验结果

### 4.1 会话总览

共进行 3 次独立正式实验（各 200 轮，不含第0阶段 20 轮验证）：

| 会话 ID | Seed | 总轮次 | valid | timeout | error | 崩溃 | mean_ms | p95_ms |
|---------|------|--------|-------|---------|-------|------|---------|--------|
| 20260417_143956 | 1776407996... | 200 | 13 (6.5%) | 187 (93.5%) | 0 | 否 | 1872 | 2003 |
| 20260417_144641 | 1776408401... | 200 | 14 (7.0%) | 186 (93.0%) | 0 | 否 | 1862 | 2003 |
| 20260417_145321 | 1776408801... | 200 | 15 (7.5%) | 185 (92.5%) | 0 | 否 | 1851 | 2003 |
| **合计** | — | **600** | **42 (7.0%)** | **558 (93.0%)** | **0** | — | — | — |

**核心观察**：
- C9800 全程稳定，无崩溃、无 probe 失败、无 `error` 类响应
- valid 比例极低（~7%），说明 C9800 对大多数畸形包静默丢弃（无回包）
- 响应时间极稳定（三次 mean 差异 < 21ms），无性能退化迹象
- p95=2003ms：95% 的响应要么在 2ms 内回包（有效回包），要么超时（≥2000ms），双峰分布

### 4.2 响应时间特征

有效回包时延极短（实测 1~5ms），而 timeout 均约 2000ms（即设定的 timeout 上限），因此 mean_ms 被 timeout 大量拉高：

| 指标 | 会话1 | 会话2 | 会话3 |
|------|-------|-------|-------|
| mean_ms（含 timeout） | 1872 | 1862 | 1851 |
| 前50轮 mean_ms | 1802 | 1882 | 1881 |
| 后50轮 mean_ms | 1961 | 1842 | 1801 |
| 时间退化比 | 1.09x | 0.98x | 0.96x |

三次退化比均接近 1.0，无显著趋势，**C9800 在整个 200 轮中性能保持稳定**。

### 4.3 变异方法有效性（3次实验合并）

下表为 600 轮中各方法触发 valid 响应的次数与比率：

| 方法名 | 总使用次数 | valid | valid 率 | 说明 |
|--------|-----------|-------|---------|------|
| `fuzz_ctrl_flags` | 53 | 7 | **13.2%** | 修改 Ctrl Header Flags 保留字段 |
| `fuzz_elem_length_zero` | 75 | 9 | **12.0%** | 将某元素 Length 置零 |
| `fuzz_elem_duplicate` | 51 | 6 | **11.8%** | 复制某个消息元素 |
| `fuzz_elem_drop` | 65 | 7 | **10.8%** | 随机删除一个消息元素 |
| `fuzz_elem_insert_unknown` | 57 | 6 | **10.5%** | 插入未知 Type 的元素 |
| `fuzz_elem_type` | 58 | 6 | **10.3%** | 随机修改某元素 Type 字段 |
| `fuzz_elem_value` | 63 | 6 | 9.5% | 随机修改某元素 Value |
| `fuzz_elem_value_type38` | 59 | 5 | 8.5% | 随机修改 WTP Board Data 值 |
| `fuzz_elem_order_shuffle` | 59 | 5 | 8.5% | 打乱消息元素顺序 |
| `brutal_bitflip` | 127 | 8 | 6.3% | 随机翻转若干 bit |
| `fuzz_capwap_wbid` | 76 | 4 | 5.3% | 修改 CAPWAP Header WBID 字段 |
| `fuzz_elem_length` | 73 | 4 | 5.5% | 随机修改某元素 Length |
| `fuzz_capwap_fragment` | 52 | 3 | 5.8% | 设置 CAPWAP 分片标志位 |
| `fuzz_ctrl_msgtype` | 18 | 0 | 0% | 修改 MsgType — 全部丢弃 |
| `brutal_shuffle_bytes` | 18 | 0 | 0% | 全字节乱序 — 全部丢弃 |
| `brutal_random_bytes` | 53 | 2 | 3.8% | 随机覆写字节段 |

**规律**：valid 率高的方法集中在**元素级结构操作**（长度置零、删除、复制、插入、乱序）和**保留字段变异**（Flags），表明 C9800 对元素层面的轻度变异有较高容忍度；`fuzz_ctrl_msgtype`（MsgType 修改）有效率为 0%，说明 MsgType=19 是 C9800 接受报文的**硬性过滤条件**。

---

## 5. 有效报文深度分析

### 5.1 所有 valid 报文共通字段

对全部 42 条 valid 记录做字段级解码统计：

| 字段 | 值 | 42条中占比 | 说明 |
|------|----|-----------|------|
| CAPWAP Version | 0 | 100% | 全部相同 |
| Hlen | 4（16字节） | 100% | 全部相同，含 MAC 可选字段 |
| MsgType | 19 | 100% | Cisco 私有 Discovery Type |
| MsgElemsLen | 231 | **100%** | **全部相同**（见下方关键发现） |

**关键发现——MsgElemsLen 是 C9800 的首要过滤条件**：

全部 42 条 valid 报文的 `MsgElemsLen` 字段均为 231，而 600 轮中绝大多数 timeout 报文的 `MsgElemsLen` 已被变异为其他值。这表明 **C9800 在解析消息元素之前，先校验 `MsgElemsLen` 字段值是否符合预期，不匹配则直接丢弃**，不回任何响应。

具体而言：`fuzz_ctrl_msgelemslen` 方法（随机修改该字段）在 600 轮中触发 0 次 valid，与上述推断完全吻合。

### 5.2 C9800 不校验的字段（异常报文仍被接受）

通过对 42 条 valid 报文的逐字段分析，发现以下字段即使取非法值，C9800 仍会响应：

#### 发现1：CAPWAP Header T 位（Data Channel 标志）不校验 ⚠️

- **RFC 5415 规定**：`T=1` 表示 Data Channel 报文；CAPWAP Control 报文（如 Discovery Request）应设 `T=0`
- **实测**：2 条报文 `T=1`（同时 `F=L=W=K=1`）仍收到 C9800 的 Discovery Response
- **涉及轮次**：Session1 round=14、Session3 round=89
- **触发方法**：`fuzz_capwap_flags`

#### 发现2：CAPWAP Header 分片位（F/L）不校验 ⚠️

- **RFC 5415 规定**：`F=1` 表示分片首包，单包 Discovery Request 不应设置分片位
- **实测**：5 条 `F=1` 或 `L=1` 的报文均收到响应；其中 1 条同时 `F=1 L=1 T=1 W=1`
- **涉及轮次**：Session1 round=118；Session2 round=72、103、134；Session3 round=34
- **触发方法**：`fuzz_capwap_fragment`、`fuzz_capwap_flags`、`fuzz_capwap_wbid`

#### 发现3：CAPWAP Header WBID 字段接受未定义值 ⚠️

- **RFC 5415 规定**：WBID=1 表示 IEEE 802.11；其他值未定义
- **实测**：WBID=12、WBID=31 的报文均被接受（各1条）
- **涉及轮次**：Session3 round=34（WBID=12）、Session3 round=110（WBID=31）
- **触发方法**：`fuzz_capwap_wbid`

#### 发现4：Control Header Flags 任意值被接受

- **RFC 5415 规定**：Ctrl Header Flags 字段为全保留（Reserved），接收方应忽略
- **实测**：flags=0xfe（几乎全位置1）、0xc9、0x8f、0x59 等均被接受（6条）
- **结论**：C9800 行为符合 RFC 规范（忽略保留位），无安全意义

#### 发现5：Control Header SeqNum 任意值被接受

- **实测**：seqnum=255、128 均 valid（各1条）
- **结论**：Discovery 阶段无状态机，不追踪序列号，属正常行为

#### 发现6：删除非必要元素后仍 valid

- `fuzz_elem_drop_required` 触发3条 valid，但解析后元素列表完整（Type 20/38/39 全在）
- **原因**：本轮随机选中删除的是非必要元素（如 Type 41 Frame Tunnel Mode、Type 44 MAC Type），不影响 C9800 响应

### 5.3 小结：C9800 输入验证模型

根据实验数据，C9800 对 Discovery Request 的处理逻辑可推断为：

```
1. UDP 端口 5246 收包
2. 校验 MsgType == 19（硬过滤，失败则丢弃）
3. 校验 MsgElemsLen == 预期值（硬过滤，失败则丢弃）
4. 尝试解析消息元素（部分宽松，元素内容变异多数被接受）
5. 不校验 CAPWAP Header 语义字段（T/F/L/W/WBID）
6. 不校验 Ctrl Header 保留字段（Flags）
7. 发送 Discovery Response（MsgType=2 或 20）
```

---

## 6. 与 OpenCAPWAP 对比分析

### 6.1 响应行为对比

| 指标 | OpenCAPWAP（灰盒） | Cisco C9800（黑盒） |
|------|-------------------|-------------------|
| valid 比率 | 0.4%~1.0% | 6.5%~7.5% |
| error 比率 | 0% | 0% |
| timeout 比率 | 98%~99% | 92.5%~93.5% |
| 崩溃 | 2/3次实验崩溃 | 0/3次 |
| DoS 现象 | 2/3次触发 | 未检测到 |
| 响应时间退化 | 轻微（1.04x） | 无（≤1.09x，随机波动） |

**关键差异**：C9800 的 valid 比率显著高于 OpenCAPWAP（7% vs < 1%）。原因是 C9800 对元素内容变异更宽容——只要整体结构框架（MsgType + MsgElemsLen）正确，元素内容的轻度改动仍会触发响应；而 OpenCAPWAP 的解析代码更严格，同时也更脆弱（容易崩溃）。

### 6.2 健壮性对比

| 维度 | OpenCAPWAP | Cisco C9800 |
|------|-----------|-------------|
| 面对畸形包的稳定性 | 差（90轮内崩溃）| 强（600轮无崩溃） |
| 输入验证严格性 | 严格但不健壮 | 宽松但稳定 |
| 错误响应 | 有（解析失败时返回 error 包） | 无（丢弃不响应） |
| 内存安全 | 存在泄漏和越界写 | 未发现问题（黑盒无法确认） |

### 6.3 协议合规性对比

| 字段 | OpenCAPWAP | Cisco C9800 |
|------|-----------|-------------|
| MsgType 校验 | 是 | 是 |
| WBID 校验 | 未测试（崩溃较快） | **否**（接受未定义 WBID） |
| T 位（Data/Ctrl）校验 | 未测试 | **否**（T=1 仍响应） |
| 分片位校验 | 未测试 | **否**（F=1 单包仍响应） |
| MsgElemsLen 校验 | 严格（不匹配崩溃或丢弃） | 严格（不匹配丢弃） |

---

## 7. 安全评估

### 7.1 协议合规性问题

根据上述分析，C9800 存在以下 RFC 5415 合规性偏差：

| 编号 | 问题 | 涉及字段 | RFC 5415 要求 | C9800 实际行为 | 安全影响 |
|------|------|---------|-------------|--------------|---------|
| ISSUE-01 | T 位不校验 | CAPWAP Hdr T | Control 报文必须 T=0 | T=1 仍响应 | 低（协议语义混淆，不导致崩溃） |
| ISSUE-02 | 分片位不校验 | CAPWAP Hdr F/L | 非分片包应 F=L=0 | F=1 单包仍响应 | 低（可能导致分片重组逻辑混乱） |
| ISSUE-03 | WBID 不校验 | CAPWAP Hdr WBID | 只定义 WBID=1(802.11) | 未定义值(12/31)仍响应 | 低（扩展性风险，未来协议版本冲突） |

### 7.2 整体评估

C9800 在本次黑盒模糊测试中表现出**高度稳定性**：600 轮畸形包注入未能引发崩溃、DoS 或性能退化。这与商用 WLC 的设计预期相符——Cisco 在实现层面做了充分的防护（主要体现为静默丢弃不符合预期的报文），而非依赖协议合规性约束。

发现的 3 个协议合规性问题（ISSUE-01~03）均为低危问题，不构成可利用的安全漏洞，但反映了 C9800 在 CAPWAP Header 语义字段校验上存在一定程度的规范偏差。

---

## 8. 图表

### 8.1 会话1 响应类型分布

![Session1 响应类型](../../charts/20260417_143956/response_type_pie.png)

### 8.2 会话1 方法有效性

![Session1 方法有效性](../../charts/20260417_143956/method_effectiveness.png)

### 8.3 会话1 响应时间序列

![Session1 响应时间](../../charts/20260417_143956/response_time_series.png)

### 8.4 多会话方法有效性热力图

![方法热力图](../../charts/compare_6sessions/method_heatmap.png)

### 8.5 多会话响应时间对比

![响应时间对比](../../charts/compare_6sessions/response_time_overlay.png)

### 8.6 会话总览（含第0阶段验证会话）

![会话总览](../../charts/compare_6sessions/session_overview.png)

---

## 9. 结论

本次对 Cisco C9800 WLC 的黑盒模糊测试共发送 600 条变异 CAPWAP Discovery Request，主要结论：

1. **C9800 高度稳定**：无崩溃、无 DoS、无性能退化，体现商用设备的工程质量。
2. **有效报文接受率 ~7%**：C9800 的核心过滤条件为 MsgType=19 + MsgElemsLen=231，满足这两个条件后对元素内容和 Header 语义字段较为宽松。
3. **发现3个协议合规性偏差**（ISSUE-01~03）：T 位、分片位、WBID 字段未按 RFC 5415 严格校验，C9800 仍会响应；均为低危，不可直接利用。
4. **与 OpenCAPWAP 形成对比**：C9800 valid 率更高但从不崩溃；OpenCAPWAP valid 率更低但在少量畸形包下即崩溃。两者体现了"商用实现 vs 开源参考实现"在健壮性上的典型差异。

---

## 附：会话数据索引

| 文件 | 路径 |
|------|------|
| 第0阶段验证 JSONL | `capwap_log/20260417_143715/records.jsonl` |
| 会话1 JSONL | `capwap_log/20260417_143956/records.jsonl` |
| 会话2 JSONL | `capwap_log/20260417_144641/records.jsonl` |
| 会话3 JSONL | `capwap_log/20260417_145321/records.jsonl` |
| 多会话对比 CSV | `charts/compare_6sessions/sessions_table.csv` |
| 会话1 图表 | `charts/20260417_143956/` |
| 会话2 图表 | `charts/20260417_144641/` |
| 会话3 图表 | `charts/20260417_145321/` |
| 多会话对比图 | `charts/compare_6sessions/` |

---

*报告生成时间：2026-04-17*  
*工具版本：capwap-discovery-fuzzer（本仓库 main 分支）*
