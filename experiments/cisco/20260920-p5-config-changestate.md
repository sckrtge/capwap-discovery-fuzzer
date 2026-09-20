# P5 实验报告：Config Status / Change State 阶段模糊测试（2026-09-20）

计划依据：`docs/fuzzer-全链路化升级计划-20260920.md` P5——"MUST 元素消融矩阵 + VSP-126 定向变异组；判定增加 config-level 信号；与 P4 基线对比产出归因表"。

## 会话五要素

| 项 | 值 |
| --- | --- |
| commit | `c3261c5`（P5 实现 + 逐轮应答摘要；前置 `c8c59c9`/`b1a41cb` 系列为阶段引擎与顺序修正） |
| seed | 定向矩阵（变体名即变异描述，无需随机）；身份池 `--identity-base-mac 10a82992b000`（config）/`10a82992c000`（change-state） |
| 参数 | `--ac-ip 192.168.10.201 --stage config\|change-state --variants all --rounds 2 --join-timeout 3 --settle 1.5 --close-wait 0.5 --stage-timeout 5 --round-gap 1`；证书 `e2ap4.crt/key`（路径传参，不入仓） |
| 目标/时间 | C9800-fresh（C9800-CL 17.14.01），2026-09-20 12:17–12:20Z；config 30 轮 106 s、change-state 16 轮 58 s |
| 原始数据 | Ubuntu `~/projects/capwap_log/20260920_p5_config/`、`20260920_p5_cs/`（各含 `session.jsonl`+`summary.json`）与 `p5_config.log`、`p5_cs.log` |

环境：LB 闸门补丁在位、cfmgr 原始字节、profile/global country CN、bf-agent 在位（同 P4）。

## 1. 运行模式（`--stage config|change-state`）

一轮 = 一条 DTLS 会话内：Discovery 前奏 → 握手 → **Join（黄金帧）** → 被变异的消息 → 判定：

- `--stage config`：Join 之后发 **被变异的 Configuration Status Request**（§8.2），读回 Configuration Status Response（MsgType 6），随后再发一条**黄金 Change State Event** 作为**存活探针**（`survives`）；
- `--stage change-state`：Join → **黄金 Configuration Status**（§2.3.1(g)：Configure 态由它进入，缺它则 Change State 被忽略——首轮实证为静默）→ **被变异的 Change State Event**（§8.6），读回 Change State Event Response（MsgType 12）；
- join 腿单独记录（`join_rc`），失败的 envelope 不会被误判为阶段结论；每轮记录 `reply_sha256`（整条应答的摘要，用于"逐字节一致"的判据）。

## 2. 判据为什么不是 Result Code（RFC 原文核对）

- **Configuration Status Response**：RFC 5415 §8.3（`docs/evidence/rfc/rfc5415.txt:6414-6430`）的 MUST 清单是 **CAPWAP Timers(12)、Decryption Error Report Period(16)、Idle Timeout(23)、WTP Fallback(40)**，外加"AC IPv4 List(2) 或 AC IPv6 List(3) 至少其一"——**不含 Result Code**。实测该应答确无 Type 33（18 个元素：10/12/16/23/31×3/32×3/37×6）。
- **Change State Event Response**：RFC 5415 §8.7（`rfc5415.txt:6615-6620`）只规定"MAY 含 Vendor Specific Payload"，实测该应答 **0 个元素**。
- 因此 P5 的判据是：**应答是否到达 + 应答的元素集合（对 §8.3 MUST 清单）+ 会话是否存活**，而不是 Result Code。

## 3. 归因表：config 阶段（15 变体 × 2 轮 = 30 轮）

**全部 30 轮 `answered`、会话存活（`survives=True`）、每变体两轮逐字节一致**；30 轮共 3 种应答：

| 变体 | §8.2 MUST 消融 | 应答 Radio Operational State | 结论 |
| --- | --- | --- | --- |
| `base` | — | **2** | 基线 |
| `omit-4`（AC Name） | 删 MUST | 2 | 不校验 |
| `omit-radio-admin` | 删 MUST(31×2) | 2 | 不校验 |
| `omit-timer36` | 删 MUST | 2 | 不校验 |
| `omit-reboot48` | 删 MUST | 2 | 不校验 |
| `omit-radname` | 删 VSP(0x0005) | 2 | 不校验 |
| `vsp126-code-ffff` | 码值改动 | 2 | 不校验码值 |
| `dup-radio-admin` / `swap-first-two` | 重复 / 乱序 | 2 | 不校验结构 |
| **`omit-vsp126`** | 删 VSP-126 | **1** | **VSP-126 缺失被察觉** |
| **`vsp126-len7`** | 7 字节头（E7 的 bug） | **1** | **解析失败被察觉** |
| **`vsp126-elemid-0`** | ElemID→0 | **1** | 同上 |
| **`vsp126-elemid-207`** | ElemID→0x00cf | **1** | 同上 |
| **`vsp126-code-0`** | 码值 0x0000 | **1** | 码值 0 等同未声明 |
| `seq-old` | SeqNum 退化为 0 | 2 | 见 §5（§4.5.3） |

**结论（本阶段唯一的强制点）**：Config Status 阶段 C9800 **不校验 RFC 5415 §8.2 的任何 MUST 元素**（逐个删除、重复、乱序、退 SeqNum 均无差异），但**会感知监管域声明 VSP-126 的存在性与可解析性**——声明缺失/头长错/ElemID 错/码值为 0 时，应答里的 **Radio Operational State 由 2 变为 1**（rid 0/1），这与 §7 监管域链"VSP-126 必须"的既有结论互相印证，并给出了一个**新的、无需 Result Code 的判据**（op state 1 vs 2）。

## 4. 归因表：change-state 阶段（8 变体 × 2 轮 = 16 轮）

**全部 16 轮 `answered`**；共 3 种应答：基线型 52B（12 轮）、`omit-radio-op` 型 62B（2 轮）、`seq-old` 型 52B（2 轮）。

| 变体 | 应答 | 结论 |
| --- | --- | --- |
| `base` / `omit-result` / `rc-1` / `rc-255` / `dup-radio-op` / `omit-vsp` | Change State Event Response（0 元素，52B） | 删掉 §8.6 的 MUST「Result Code(33)」、或谎报 Result Code=1/255，**控制器均无反应** |
| **`omit-radio-op`** | 62B：Change State Event Response（0 元素）**+ Configuration Update Request（MsgType 7，2 个 FIPS VSP 0x00fc）** | **删掉 §8.6 的 MUST「Radio Operational State(32)」触发控制器反向推送配置**（Run 态配置推送的开始），而非拒绝 |
| `seq-old` | 52B，但应答 SeqNum = 0（与请求同） | 见 §5 |

## 5. 两处与 RFC 原文的偏差（本研究实测，非推断）

1. **§4.5.3 的重复序号规则未被实现**（`rfc5415.txt:3168-3172`）：该节要求"收到与上一条**同序号**的请求时，必须重发缓存的响应而不重新处理请求；收到**更旧**序号的请求必须忽略"。实测 `seq-old` 变体（Config Status / Change State 的 SeqNum 退回 0，与 Join 的 0 重复）得到的是 **同序号的正常响应**（Config Status Response，MsgType 6；Change State Event Response），既没有重发缓存的 Join Response，也没有静默忽略。
2. **§8.3 的 MUST 清单未满足**：该节要求"AC IPv4 List(2) 或 AC IPv6 List(3) 至少其一 MUST 包含"（`rfc5415.txt:6425-6430`），实测 Configuration Status Response 两者都没有（它发的是 CAPWAP Control IPv4 Address，Type 10，§4.6.9，与 §4.6.2 的 AC IPv4 List 不是同一个元素）。其余四条 MUST（12/16/23/40）均在。
   - 注：RFC 5416 §5.8（`rfc5416.txt:1471-1495`）只追加 MAY 元素，不放松该 MUST 清单。

两处均为低危合规偏差（不影响 join/注册，属"容错过度/元素替换"类），登记备查。

## 6. 结论与后续

1. **对 fuzzing 的意义**：Config/Change State 阶段不是有效的拒绝面——除监管域声明外，控制器对该阶段几乎所有输入都不设防；P5 的主要收获是**把"监管域声明"钉成一个可观测的判据（op state 2→1）**，以及两处 RFC 偏差。
2. **对后续阶段的意义**：`omit-radio-op` 触发的 MsgType 7 推送说明"配置推送"是由**radio 状态确认**驱动的，这为 P6（Run 态/反馈闭环）提供了新的观测点：可以用 Change State 的 radio 状态字段当作开关来复现/抑制配置流。
3. **未做**：本阶段未做 btrace 抽样核对（P4 的 §7 已有同法工具 `tools/btrace_correlate.py`，可用于后续把"op state 1 vs 2"对到 wncd trace 的监管域检查行）。
4. **工具**：`tools/p5_config_probe.py`（单轮 join+config/change-state 并打印完整应答解析，用于差异定位）。
