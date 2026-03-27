
# CAPWAP Discovery Fuzzer

An academic CAPWAP Discovery Request/Response fuzzing tool for security research and protocol testing.

# CAPWAP 发现协议模糊测试工具

用于安全研究和协议测试的学术性CAPWAP发现请求/响应模糊测试工具。

## Features / 功能特性

- **Protocol Support / 协议支持**: CAPWAP Discovery Request/Response (RFC 5415)
- **Multiple Fuzzing Strategies / 多种模糊测试策略**:
  - Safe fuzzing methods (header fields, message elements)
  - 安全的模糊测试方法（头部字段、消息元素）
  - Brutal fuzzing methods (byte-level mutations)
  - 暴力模糊测试方法（字节级变异）
  - Composite fuzzing (combining multiple methods)
  - 复合模糊测试（组合多种方法）
- **Multiple Modes / 多种模式**:
  - Unicast mode (target specific AC)
  - 单播模式（针对特定AC）
  - Broadcast mode (discover ACs in network)
  - 广播模式（发现网络中的AC）
  - PCAP-based fuzzing (load request from capture)
  - 基于PCAP的模糊测试（从抓包文件加载请求）
  - Random request generation
  - 随机请求生成
- **Response Analysis / 响应分析**:
  - Automatic response classification (valid/error/timeout)
  - 自动响应分类（有效/错误/超时）
  - Detailed error type identification
  - 详细的错误类型识别
  - Response structure parsing and validation
  - 响应结构解析与验证
- **Logging & Replay / 日志记录与回放**:
  - JSON-based request/response logging
  - 基于JSON的请求/响应日志记录
  - Request replay for crash reproduction
  - 请求回放用于崩溃复现
  - Comprehensive statistics and reports
  - 全面的统计和报告

## Installation / 安装

### Requirements / 依赖

- Python 3.10+
- Scapy 2.5+
- Typer (for CLI)

### Install from source / 从源码安装

```bash
git clone https://github.com/sckrtge/capwap-discovery-fuzzer.git
cd capwap-discovery-fuzzer
pip install -e .
```

### Development setup / 开发环境设置

```bash
pip install -e ".[test]"
```

## Usage / 使用说明

### Basic Command / 基本命令

```bash
python -m capwap_discovery_fuzzer --help
```

### Basic Examples / 基本示例

#### 1. Unicast Fuzzing with PCAP / 使用PCAP的单播模糊测试

```bash
python -m capwap_discovery_fuzzer \
  --pcap ./pcaps/sample_discovery_request.pcap \
  --ac-ip 192.168.10.128 \
  --ac-port 5246 \
  --rounds 10 \
  --timeout 3 \
  --seed 1337
```

#### 2. Broadcast Discovery / 广播发现

```bash
python -m capwap_discovery_fuzzer \
  --broadcast \
  --ac-port 5246 \
  --rounds 50 \
  --timeout 3
```

#### 3. Replay JSON Requests / 回放JSON请求

```bash
python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.10.128 \
  --ac-port 5246 \
  --replay-json-dir ./requests_json \
  --rounds 5
```

#### 4. Random Request Generation / 随机请求生成

```bash
python -m capwap_discovery_fuzzer \
  --ac-ip 192.168.10.128 \
  --ac-port 5246 \
  --rounds 20 \
  --timeout 2.5
```

### Command Line Options / 命令行选项

| Option / 选项 | Description / 描述 | Default / 默认值 |
|--------------|-------------------|-----------------|
| `--pcap` | PCAP file containing CAPWAP Discovery Request / 包含CAPWAP发现请求的PCAP文件 | None |
| `--ac-ip` | Target AC IP address (unicast mode) / 目标AC IP地址（单播模式） | None |
| `--ac-port` | Target AC control port / 目标AC控制端口 | 5246 |
| `--broadcast` | Use UDP broadcast for CAPWAP Discovery / 使用UDP广播进行CAPWAP发现 | False |
| `--rounds` | Rounds of fuzzing iterations / 模糊测试迭代轮数 | 1 |
| `--seed` | Random seed for fuzzing / 模糊测试随机种子 | System time |
| `--timeout` | Timeout for waiting response (seconds) / 等待响应的超时时间（秒） | 3.0 |
| `--sleep` | Sleep seconds per fuzzing round / 每轮模糊测试的睡眠时间（秒） | 1.0 |
| `--replay-json-dir` | Directory containing JSON request logs to replay / 包含要回放的JSON请求日志的目录 | None |

**Note / 注意**: Either `--ac-ip` (unicast) or `--broadcast` must be specified. / 必须指定`--ac-ip`（单播）或`--broadcast`。

## Fuzzing Methods / 模糊测试方法

### Safe Fuzzing Methods / 安全模糊测试方法

1. **CAPWAP Header Fuzzing / CAPWAP头部模糊测试**
   - Version field mutation / 版本字段变异
   - Header length field mutation / 头部长度字段变异
   - Fragment offset field mutation / 分片偏移字段变异

2. **Control Header Fuzzing / 控制头部模糊测试**
   - Sequence number mutation / 序列号变异
   - Message elements length mutation / 消息元素长度变异

3. **Message Element Fuzzing / 消息元素模糊测试**
   - Message type mutation / 消息类型变异
   - Message length mutation / 消息长度变异
   - Message value mutation / 消息值变异
   - Specific message type fuzzing (Type 38, 39) / 特定消息类型模糊测试（类型38、39）

4. **Structural Fuzzing / 结构模糊测试**
   - Message duplication / 消息复制
   - Last message dropping / 最后消息丢弃
   - Message shuffling / 消息重排
   - CAPWAP flags mutation / CAPWAP标志位变异

### Brutal Fuzzing Methods / 暴力模糊测试方法

1. **Byte-level Mutations / 字节级变异**
   - Random byte flipping / 随机字节翻转
   - Random byte insertion / 随机字节插入
   - Random byte deletion / 随机字节删除
   - Byte shuffling / 字节重排
   - Segment duplication / 片段复制
   - Segment reversal / 片段反转

### Composite Fuzzing / 复合模糊测试

The tool combines multiple safe and brutal methods in each iteration for more effective fuzzing. / 工具在每次迭代中组合多种安全和暴力方法，以实现更有效的模糊测试。

## Output and Logging / 输出与日志记录

### Directory Structure / 目录结构

```
capwap_log/
├── YYYYMMDD_HHMMSS/          # Session directory / 会话目录
│   ├── fuzzer.log           # Text log file / 文本日志文件
│   └── responses/           # JSON response files / JSON响应文件
│       └── response_*.json  # Individual response records / 单个响应记录
```

### JSON Response Format / JSON响应格式

Each response is saved as a JSON file with the following structure: / 每个响应保存为包含以下结构的JSON文件：

```json
{
  "request_bytes": "hex string",
  "request_structure": {...},
  "response_bytes": "hex string",
  "parsed_response": {...},
  "response_type": "valid|error|timeout",
  "error_type": "ErrorClassName",
  "request_info": {
    "iteration": 1,
    "method_chain": ["fuzz_capwap_header", "brutal_random_bytes"]
  }
}
```

### Console Output / 控制台输出

The tool provides real-time progress and summary tables: / 工具提供实时进度和摘要表格：

```
CAPWAP Discovery Fuzzing
[+] PCAP file: ./pcaps/sample_discovery_request.pcap
[+] Mode      : Unicast
[+] Target    : 192.168.10.128:5246
[+] Rounds    : 10
[*] Using random seed: 1711543200

Fuzzing CAPWAP Discovery [████████████████████] 10/10

CAPWAP Fuzzing/Replay Summary
┌────────┬───────┐
│ Type   │ Count │
├────────┼───────┤
│ valid  │ 5     │
│ timeout│ 3     │
│ error  │ 2     │
│ total  │ 10    │
└────────┴───────┘

Error Type Distribution
┌──────────────────────────┬───────┐
│ Error Type               │ Count │
├──────────────────────────┼───────┤
│ MissingCapwapHeaderError │ 1     │
│ UnexpectedMsgTypeError   │ 1     │
└──────────────────────────┴───────┘
```

## Project Structure / 项目结构

```
src/capwap_discovery_fuzzer/
├── __init__.py
├── __main__.py
├── capwap_discovery_fuzzer.py  # Main fuzzer class / 主模糊测试类
├── cli.py                      # Command line interface / 命令行接口
├── errors.py                   # Custom exception classes / 自定义异常类
├── payload_fuzzer.py           # Fuzzing methods / 模糊测试方法
├── request_creater.py          # Request generation / 请求生成
├── response_parser.py          # Response parsing / 响应解析
└── utils.py                    # Utility functions / 工具函数

tests/
└── test_capwap_discovery_fuzzer.py

pcaps/
└── sample_discovery_request.pcap  # Example CAPWAP request / 示例CAPWAP请求

run_fuzzing.sh                    # Example unicast script / 单播示例脚本
run_fuzzing_broadcast.sh          # Example broadcast script / 广播示例脚本
```

## License / 许可证

MIT License
