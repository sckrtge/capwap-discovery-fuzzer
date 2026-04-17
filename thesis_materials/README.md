# 毕业设计论文素材索引

**项目**：针对 CAPWAP 协议的安全分析工具设计与实现  
**学校**：重庆大学  
**整理时间**：2026-04-17

---

## 目录结构

```
thesis_materials/
├── README.md                        ← 本文件（素材索引）
├── charts/
│   ├── opencapwap/                  ← OpenCAPWAP 实验图表
│   │   ├── session1_process_memory.png       内存增长曲线（含崩溃标记）
│   │   ├── session2_process_memory.png       会话2内存曲线（极早崩溃）
│   │   ├── session3_process_memory.png       会话3内存曲线（未崩溃持续增长）
│   │   ├── session1_response_type_pie.png    响应类型分布饼图
│   │   ├── session1_method_effectiveness.png 变异方法有效性柱状图
│   │   ├── session1_response_time_series.png 响应时间折线图
│   │   ├── memory_overlay.png               3次会话内存趋势对比
│   │   ├── mttc_comparison.png              MTTC 可重复性验证
│   │   ├── method_heatmap.png               变异方法热力图（3次合并）
│   │   ├── response_time_overlay.png        响应时间趋势对比
│   │   └── sessions_table.csv               会话数据汇总表
│   └── cisco/
│       ├── response_type_pie.png            响应类型分布饼图
│       ├── method_effectiveness.png         变异方法有效性柱状图
│       ├── response_time_series.png         响应时间折线图
│       ├── session_overview.png             多会话总览
│       ├── method_heatmap.png               变异方法热力图
│       ├── response_time_overlay.png        响应时间趋势对比
│       └── sessions_table.csv              会话数据汇总表
└── data/
    ├── opencapwap/
    │   ├── 20260415_165736/         ← 会话1（89轮，第90轮崩溃，DoS触发）
    │   │   ├── summary.json
    │   │   ├── session.json
    │   │   ├── crash_report.json
    │   │   ├── crash_sequence.jsonl
    │   │   ├── suspected_event.json
    │   │   └── process_monitor.csv
    │   ├── 20260415_170825/         ← 会话2（10轮，第10轮崩溃，极早Crash）
    │   │   ├── summary.json
    │   │   ├── session.json
    │   │   ├── crash_report.json
    │   │   └── crash_sequence.jsonl
    │   └── 20260415_170915/         ← 会话3（494轮，未崩溃，DoS持续）
    │       ├── summary.json
    │       ├── session.json
    │       ├── suspected_event.json
    │       └── process_monitor.csv
    └── cisco/
        ├── 20260417_143956/         ← Cisco 会话1（200轮）
        │   ├── summary.json
        │   └── session.json
        ├── 20260417_144641/         ← Cisco 会话2（200轮）
        │   ├── summary.json
        │   └── session.json
        └── 20260417_145321/         ← Cisco 会话3（200轮）
            ├── summary.json
            └── session.json
```

---

## 核心实验结论速查

### OpenCAPWAP 灰盒实验

| 漏洞 | 类型 | 根因文件 | 复现 |
|------|------|---------|------|
| VULN-01 | DoS（WTP槽位耗尽） | `ACMainLoop.c:373`（资源分配在验证之前） | ✅ |
| VULN-02 | NULL Session → SIGSEGV | `ACMainLoop.c:764` + `CWSecurity.c:302` | ✅ |
| VULN-03 | 同VULN-02，极早触发 | 同上 | ✅ |

**崩溃共同路径**：`brutal_*` 字节变异将报文首字节低4位置为 `0x1`（`CW_PACKET_CRYPT`）→ AC 误判为 DTLS 包 → `SSL_read(NULL)` → SIGSEGV

**DoS 触发条件**：畸形包（解析失败）进入 `else` 分支 → 分配 WTP 槽位 → `gActiveWTPs++` → 15条即耗尽

### Cisco C9800 黑盒实验

| 指标 | 值 |
|------|----|
| 总轮次 | 600（3×200） |
| valid 率 | ~7%（核心条件：MsgType=19 + MsgElemsLen=231） |
| 崩溃/DoS | 无 |
| 协议合规偏差 | 3项（T位/分片位/WBID 不校验，低危） |

---

## 论文章节建议对应

| 论文章节 | 对应素材 |
|---------|---------|
| 1. 绪论 | 背景：CAPWAP 协议现状；研究意义：OpenCAPWAP漏洞 |
| 2. 相关工作 | CAPWAP RFC 5415；模糊测试方法综述 |
| 3. 系统设计与实现 | `CLAUDE.md` 架构描述；`src/` 源代码 |
| 4.1 实验环境 | `experiments/opencapwap/experiment_report.md` §1 |
| 4.2 灰盒实验结果 | §4 + §5 图表；`data/opencapwap/` |
| 4.3 漏洞复现与根因 | §6 + §7；GDB backtrace |
| 4.4 黑盒对比实验 | `experiments/cisco/experiment_report.md` |
| 5. 结论 | 三个漏洞总结；修复建议；与商用设备对比 |

---

## 工具代码位置（论文引用用）

```
src/capwap_discovery_fuzzer/
├── cli.py                    # CLI 入口（Typer）
├── capwap_discovery_fuzzer.py  # 核心 Fuzzer 类
├── payload_fuzzer.py         # 31 个变异方法（21 safe + 10 brutal）
├── request_creater.py        # CAPWAP 报文构造（Scapy）
├── response_parser.py        # 响应解析与分类
├── errors.py                 # 异常层级
└── vendors/
    ├── opencapwap/fuzzer.py  # 灰盒扩展（进程监控 + 三态检测）
    └── cisco/                # Cisco C9800 专用模式
```
