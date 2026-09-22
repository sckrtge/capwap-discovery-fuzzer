# D3 · Discovery 变异强化 C9800 在环验证报告（2026-09-22）

> 计划：`docs/Discovery变异强化与阶段开关计划-20260921.md` §D3。**结论：M1/M2 归因闭环完成，"新策略在 C9800 跑通"成立**——跑通的含义包含两点：① 管道与判定链在环稳定工作（A 组 30/30 answered、全轮设备侧观测对齐）；② **归因结论本身是"入口硬闸门"画像**：长度交叉与分片面在该目标上 100% 被入口丢弃，金丝雀通道不可达（见 §4，这是目标边界，不是工具缺陷）。

## 1. 五要素

| 项 | 值 |
| --- | --- |
| 代码 | 本地提交 `7ad250d`（分支 `feature/session-fuzzing`，pytest 206/206），SFTP 同步 Ubuntu 工作树 `~/projects/fuzzing/capwap-discovery-fuzzer/` |
| 目标 | C9800-fresh，192.168.10.201:5246（明文控制通道；uptime 1d+，无补丁影响——Discovery 不经 LB 闸门） |
| seed | 20260922（各组相同） |
| 参数 | `--round-gap 1 --stage-timeout 5`（默认），身份=默认单身份（Cisco 黄金种子，与历史基线可比） |
| 时间/数据 | 2026-09-22 02:43–03:35Z；原始 jsonl 在 Ubuntu `~/projects/fuzzing/discovery-d3/<组>/`（session.jsonl + summary.json），汇总快照在本工作区 `docs/evidence/re-20260922/d3-summaries/` |

## 2. 七组结果

| 组 | 内容 | answered/rounds | silent | leak |
| --- | --- | --- | --- | --- |
| A | `base`（锁定基线/阴性对照）×30 | **30/30** | 0 | 0 |
| B | m1 冒烟 ×5 | 0/20 | 20 | 0 |
| C | m2 冒烟 ×5 | 5/45（全部来自 `frag-rsvd-nonzero`） | 40 | 0 |
| D | m3+m4+m5 冒烟 ×3 | 42/60 | 18 | 0 |
| E | m1 扩量 ×10 | 0/40 | 40 | 0 |
| F | m2 扩量 ×10 | 10/90（全部来自 `frag-rsvd-nonzero`） | 80 | 0 |
| G | `classic-random`（未锁定对照）×200 | 0/200 | 200 | 0 |

**设备侧观测（与 fuzz 并行）**：SNMP 10s 轮询全程 40 分钟（`d3-summaries/snmp-poll.txt`）——sysUpTime 连续递增、wncd/wncmgrd 进程表恒定；事后 CLI：无新 `%PMAN` 事件、`bootflash:core` 无当日新文件、`show ap summary` **AP 数 = 0**（Discovery 不产生幻影 AP，与 join 侧 P4.5 行为明确区分）。⇒ 全程无 ANOMALY，未触发停止条件。

## 3. D 组归因明细（过滤器画像）

| 变体（×3） | answered | 说明 |
| --- | --- | --- |
| hdr-version-1 / hdr-version-15 | 0/3 | Preamble Version ≠ 0 → 丢 |
| hdr-ptype-dtls | 0/3 | Type=1 转 DTLS 解析器后丢 |
| plain-non-disc / plain-echo / msgtype-undef | 0/9 | **§4.1 合规静默的阴性对照锚点验证通过**（明文通道非 Discovery 必丢） |
| hdr-wbid-0/2/31 | 3/3 | WBID 保留值不校验（RFC 偏差候选） |
| hdr-t-bit / hdr-k-bit / hdr-m0 / hdr-rid-31 / hdr-flags-nonzero / hdr-wsi-present | 各 3/3 | T/K/M/RID/保留 Flags/WSI 全部容忍 |
| nest-depth-4 / nest-len-bad / elemid-sweep | 各 3/3 | VSP 嵌套与未分配 ElemID 容忍（与 P5"内容不校验"一致） |
| seq-jump / seq-dup | 各 3/3 | 序号不校验（§4.5.3 偏差旁证） |

## 4. 结论

1. **m1 长度交叉：0/60，100% 入口丢弃**（MsgElemsLen/元素长度/HLEN 任何不一致都不产生应答）⇒ **金丝雀（over-read）通道在此目标不可达**：C9800 在解析前校验长度一致性并静默丢弃，"声明>实际"的报文根本进不了元素解析器。这是 oracle 边界的实测结论：对**最新固件**做泄漏类探测，长度交叉路径必须换承载（如加密后通道或其它厂商实现），明文 Discovery 上无效。
2. **m2 分片：F 位是唯一硬闸门**——8 个 F=1 变体共 85 轮全部静默（明文 Discovery 路径无任何重组行为迹象），唯一 answered 的分片层变体是 `frag-rsvd-nonzero`（F=0，只动 3 个保留位，15/15）⇒ 分片变异面在明文 Discovery 上同样**不可达**，与 m1 同属"入口结构校验"边界。
3. **入口闸门画像（本研究推断，实测支撑）**：C9800 明文 Discovery 的可变空间 = 头部大部分位（WBID/T/K/M/RID/Flags/WSI）+ 元素内容 + 序号；**硬闸门仅三处**：Preamble（Version=0 且 Type=0）、MsgType ∈ Discovery 系、帧结构完整性（长度一致 + F=0）。
4. **A 组确定性**：30 条应答长度恒 102B、canary 全程 extra=0，唯一变化字节 = offset 100（逐轮 +1 计数器）——对照底板高度稳定。
5. **G 组基线**：`classic-random`（随机元素生成器）0/200。注意与历史"未锁定 1.3%"**不可比**：1.3% 来自经典引擎对有效种子的链式变异（较温和），classic-random 是全新随机元素生成器（更破坏性）。同口径对照应经 `cli.py` 经典入口跑，留 D5/论文素材轮。

## 5. 对计划的偏离（已记录）

- E/F 扩量从计划的 ×30/变异、×200/层 缩减为 **×10/变异**：冒烟已给出统计强度（m1 若真实回答率 10%，20 连静默概率 ≈12%、60 连 ≈0.1%；扩量确认稳定性即可），数千轮纯静默违背低负载纪律。200 轮预算改投 G 组。
- D2.3 分层采样的"接入 fuzzer monitor"仍未做（本轮用 tools/ 侧 SNMP 轮询脚本替代联调，接口已验证）。

## 6. 下一步

- **D4（ZyWALL）前置已满足**（D3 通过）：按 Z 线计划授权 Z1（解包）起执行；同一套 M1–M5 变异集在其上对照——特别是 m1/m2 在 ZyWALL 上是否同样入口丢弃（预期差异点，双厂商画像核心）。
- 阴性对照锚点（§4.1 静默）与入口闸门画像可直接进论文素材库（P7 持续化）。
