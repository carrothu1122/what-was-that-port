# TCP 端口扫描工具集

本仓库包含三种基于不同原理的 TCP 端口扫描器，使用 Python 实现，用于判断目标主机端口的开放状态。

## 当前整合状态

`tcp_scanner` 已整理为标准 Python package，可从仓库根目录通过模块方式运行：

```bash
python -m tcp_scanner --help
```

统一入口包含三类功能：

```bash
# TCP Connect 扫描（普通权限通常可运行）
python -m tcp_scanner scan 192.168.1.1 -p 22,80,443 --mode connect

# TCP SYN 扫描（需要 scapy，通常需要 sudo/root）
sudo python -m tcp_scanner scan 192.168.1.1 -p 1-1024 --mode syn

# TCP FIN 扫描（需要 scapy，通常需要 sudo/root）
sudo python -m tcp_scanner scan 192.168.1.1 -p 21,22,80 --mode fin

# 服务指纹识别
python -m tcp_scanner fingerprint 192.168.1.1 -p 22,80,443

# ICMP 主机存活探测（通常需要 sudo/root）
sudo python -m tcp_scanner ping 192.168.1.1
```

前端接入可使用 JSON 输出：

```bash
python -m tcp_scanner scan 127.0.0.1 -p 22 --mode connect --json
```

输出格式为数组，每个端口一条记录：

```json
[
    {
        "ip": "127.0.0.1",
        "host_status": "online",
        "method": "TCP Connect",
        "port": 22,
        "port_status": "open",
        "service": null
    }
]
```

如果需要中文状态：

```bash
python -m tcp_scanner scan 127.0.0.1 -p 22 --mode connect --json --lang zh
```

如需把扫描结果同时导出到文件，可开启导出选项：

```bash
python -m tcp_scanner scan 127.0.0.1 -p 22 --mode connect --export-results --export-dir ./exports
```

如果不指定 `--export-dir`，程序会在执行后提示你输入导出目录；未输入时则不会写文件。三类命令（scan、fingerprint、ping）都支持该选项。

服务识别也支持相同 JSON 格式，`service` 会尽量填入识别结果：

```bash
python -m tcp_scanner fingerprint 127.0.0.1 -p 22,80 --json
```

新增/合并模块：

| 文件 | 功能 |
|------|------|
| `cli.py` / `__main__.py` | 统一命令行入口 |
| `host_discovery.py` | ICMP 主机存活探测 |
| `fingerprints.py` | 服务指纹库 |
| `service_fingerprint.py` | TCP 服务识别 |

已修复：

- `tcp_connect_scanner.py` 原本没有实际调用 `connect/connect_ex`，会把合法端口误判为 open。
- 包内导入已兼容 `python -m tcp_scanner ...` 方式。
- socket 创建异常会被转换为单端口 `error` 结果，不再中断整批扫描。

| 文件 | 扫描类型 | 原理 | 权限要求 |
|------|---------|------|---------|
| `tcp_connect_scanner.py` | TCP Connect 扫描 | 完整 TCP 三次握手 | 普通用户 |
| `tcp_syn_scanner.py` | TCP SYN 扫描（半开放扫描） | 仅发送 SYN，收到 SYN/ACK 后发 RST 断开 | **需要 root/sudo** |
| `tcp_fin_scanner.py` | TCP FIN 扫描 | 发送 FIN 标志包，根据 RFC 793 行为判断 | **需要 root/sudo** |

---

## 1. TCP Connect 扫描 (`tcp_connect_scanner.py`)

### 原理

利用操作系统完整的 `connect()` 系统调用与目标端口进行三次握手：

- **连接成功** → 端口开放（`open`）
- **连接被拒绝（OSError）** → 端口关闭（`closed`，原始错误码保留在 `error_code`）
- **超时** → 端口可能被过滤（`filtered`）

这是最基础的 TCP 扫描方式，无需特殊权限，但会在目标主机留下连接日志，隐蔽性较差。

### 依赖

- 纯 Python 标准库（`socket`、`concurrent.futures`），无需额外安装。

### 用法

该文件即可作为模块导入，也可直接运行调试。

#### 模块导入

```python
from tcp_scanner.tcp_connect_scanner import TCPConnectScanner, print_scan_results
from tcp_scanner.utils import parse_ports

scanner = TCPConnectScanner(timeout=1.0)
ports = parse_ports("22,80,443")
results = scanner.scan_ports("192.168.1.1", ports, max_workers=50)
print_scan_results(results)
```

#### 直接运行

修改文件底部的调试参数后运行：

```bash
python tcp_connect_scanner.py
```

### 扫描结果

每条结果包含以下字段：

| 字段 | 说明 |
|------|------|
| `host` | 目标主机 IP 或域名 |
| `port` | 目标端口号 |
| `status` | 端口状态：`open` / `closed` / `filtered` / `error` |
| `error_code` | socket 错误码（成功时为 0，即 connect()返回0） |
| `error_message` | 详细错误信息（使用 PPT 术语） |

#### 示例输出

```
------------------------------------------------------------------------------------------
Host              Port      Status         Error Code   Message
------------------------------------------------------------------------------------------
192.168.1.1       22        open           0            connect()返回0
192.168.1.1       21        closed         10061        SOCKET-ERROR (errno=10061)
192.168.1.1       443       filtered       None         timed out
------------------------------------------------------------------------------------------
```

---

## 2. TCP SYN 扫描 (`tcp_syn_scanner.py`)

### 原理

也被称为**半开放扫描（Half-open scanning）**。程序构造并发送 SYN 数据包，根据目标返回的 TCP 标志位判断：

- **收到 SYN/ACK** （标志位 `0x12`）→ 端口开放（`open`），随后发送 RST 断开（不完成三次握手）
- **收到 RST** （标志位 `0x04` 或 `0x14`）→ 端口关闭（`closed`）
- **无响应** → 可能被防火墙过滤（`filtered`）
- **收到 ICMP 不可达** → 被过滤（`filtered`）

由于不完成完整的三次握手，目标可能不会记录连接日志，隐蔽性较高。

### 依赖

```bash
pip install scapy
```

### 用法

#### 模块导入

```python
from tcp_scanner.tcp_syn_scanner import TCPSYNScanner, print_scan_results
from tcp_scanner.utils import parse_ports

scanner = TCPSYNScanner(timeout=2.0)
ports = parse_ports("22,80,443")
results = scanner.scan_ports("192.168.1.1", ports, max_workers=50)
print_scan_results(results)
```

#### 直接运行（调试）

修改文件底部调试参数后运行（需管理员/root 权限）：

```bash
# Linux
sudo python3 tcp_syn_scanner.py

# Windows（以管理员身份运行 cmd/powershell）
python tcp_syn_scanner.py
```

### 扫描结果

每条结果包含以下字段：

| 字段 | 说明 |
|------|------|
| `host` | 目标主机 IP 或域名 |
| `port` | 目标端口号 |
| `status` | 端口状态：`open` / `closed` / `filtered` / `error` |
| `response_flags` | 目标返回的 TCP 标志位（如 `SA` 表示 SYN/ACK） |
| `error_message` | 详细描述信息 |

#### 示例输出

```
----------------------------------------------------------------------------------------------------
Host              Port      Status      Flags        Message
----------------------------------------------------------------------------------------------------
192.168.1.1       22        open        SA           Received SYN/ACK
192.168.1.1       80        closed      RA           Received RST
192.168.1.1       443       filtered    None         No response
----------------------------------------------------------------------------------------------------
```

---

## 3. TCP FIN 扫描 (`tcp_fin_scanner.py`)

### 原理

根据 RFC 793，向目标端口发送 FIN 标志的数据包。PPT 要求的三种情况：

- **收到 ACK** → 存在对应连接（`有连接(ACK)`）
- **直接丢弃（无响应）** → 端口打开且无连接（`打开(丢弃)`）
- **收到 RST** → 端口关闭（`关闭(RST)`）
- **收到 ICMP 不可达**（type=3, code=1/2/3/9/10/13）→ 被过滤（`filtered`）

FIN 扫描比 SYN 扫描更加隐蔽，因为关闭的端口才会回复 RST，而开放的端口会忽略 FIN 包。但某些操作系统（如 Windows）的实现不符合 RFC 793，可能无法准确判断。

### 依赖

```bash
pip install scapy
```

### 用法（命令行）

```bash
# Linux（需要 sudo）
sudo python3 tcp_fin_scanner.py 192.168.1.1 -p 21,22,80

# 扫描端口范围
sudo python3 tcp_fin_scanner.py 192.168.1.1 -p 1-1024

# 自定义超时和重试
sudo python3 tcp_fin_scanner.py 192.168.1.1 -p 22,80,443 -t 2.0 -r 2

# 显示所有端口（包括 closed）
sudo python3 tcp_fin_scanner.py 192.168.1.1 -p 1-100 --show-all

# 增加探测间隔，降低扫描速率和网络负载
sudo python3 tcp_fin_scanner.py 192.168.1.1 -p 1-1000 -d 0.1
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `target` | 目标 IPv4 地址（必填） | - |
| `-p, --ports` | 扫描端口，如 `21,22,80` 或 `1-1024`（必填） | - |
| `-t, --timeout` | 等待响应超时时间（秒） | `1.0` |
| `-r, --retries` | 无响应时的重试次数 | `1` |
| `-d, --delay` | 每个端口之间的延迟（秒） | `0.05` |
| `--show-all` | 显示所有端口（包括 closed） | 不显示 |

### 扫描结果示例

```
========== TCP FIN 扫描 ==========
目标地址：192.168.1.1
端口数量：3
超时时间：1.0 秒
重试次数：1
==================================

PORT      STATE                REASON
----------------------------------------------------------------------
22        关闭(RST)            收到RST — 端口关闭
21        打开(丢弃)           无响应 — 端口打开且无连接, 直接丢弃
443       filtered             收到 ICMP 不可达，type=3，code=13

========== 扫描汇总 ==========
打开(丢弃)  ：1  ← 端口打开且无连接，直接丢弃
关闭(RST)  ：1  ← 端口关闭，返回RST
有连接(ACK)：0  ← 存在对应连接，返回ACK
filtered   ：1
unknown    ：0
error      ：0
==============================

说明：FIN 扫描中，端口打开且无连接时目标直接丢弃 FIN 包（无响应）；
端口关闭时返回 RST；若已存在连接则返回 ACK。
```

---

## 4. 整合集成指南

### 4.1 统一数据模型（`models.py`）

三种扫描器共用 `models.py` 中的 dataclass，统一访问方式为 `result.host`、`result.port`、`result.status`、`result.error_message`：

| 类 | 所属扫描器 | status 可选值 |
|----|-----------|--------------|
| `TCPConnectScanResult` | Connect | `open` / `closed` / `filtered` / `error` |
| `TCPSYNScanResult` | SYN | `open` / `closed` / `filtered` / `error` |
| `TCPFINScanResult` | FIN | `closed` / `open\|filtered` / `filtered` / `unknown` / `error` |

### 4.2 公共工具（`utils.py`）

```python
from tcp_scanner.utils import parse_ports, validate_target

ports = parse_ports("22,80,443")     # → [22, 80, 443]
ports = parse_ports("1-1024")        # → [1, 2, ..., 1024]
ip   = validate_target("192.168.1.1") # 校验并返回 IPv4 字符串
```

### 4.3 快速调用示例

```python
# ---- TCP Connect ----
from tcp_scanner.tcp_connect_scanner import TCPConnectScanner
from tcp_scanner.utils import parse_ports

scanner = TCPConnectScanner(timeout=1.0)
results = scanner.scan_ports("192.168.1.1", parse_ports("22,80,443"))
for r in results:
    print(f"{r.host}:{r.port} → {r.status}")

# ---- TCP SYN ----
from tcp_scanner.tcp_syn_scanner import TCPSYNScanner

scanner = TCPSYNScanner(timeout=2.0)
results = scanner.scan_ports("192.168.1.1", parse_ports("22,80,443"))
for r in results:
    print(f"{r.host}:{r.port} → {r.status}")

# ---- TCP FIN ----
from tcp_scanner.tcp_fin_scanner import scan_ports as fin_scan_ports

results = fin_scan_ports("192.168.1.1", parse_ports("22,80,443"), timeout=1.0)
for r in results:
    print(f"{r.host}:{r.port} → {r.status}")
```

### 4.4 完整整合示例

完整的四种整合方案（分别调用、统一接口、对比扫描、异常安全包装）见：

📁 **[`examples/integration_demo.py`](examples/integration_demo.py)**

核心 API 签名速查：

| 模块 | 主要入口 | 返回类型 |
|------|---------|---------|
| `tcp_connect_scanner` | `TCPConnectScanner(timeout).scan_ports(host, ports)` | `List[TCPConnectScanResult]` |
| `tcp_syn_scanner` | `TCPSYNScanner(timeout).scan_ports(host, ports)` | `List[TCPSYNScanResult]` |
| `tcp_fin_scanner` | `fin_scan_port(target, port, timeout, retries)` | `TCPFINScanResult` |
| `tcp_fin_scanner` | `scan_ports(target, ports, timeout, retries, delay)` | `List[TCPFINScanResult]` |

### 4.5 整合注意事项

| 要点 | 说明 |
|------|------|
| **权限** | `syn` 和 `fin` 模式在 Linux 上需 `sudo`，Windows 上需管理员运行 |
| **依赖** | `connect` 纯标准库可用；`syn` 和 `fin` 需 `pip install scapy` |
| **导入安全** | FIN 的 `main()` 仅在 `__name__ == "__main__"` 时执行，`import` 安全 |
| **数据模型** | 三种扫描结果统一使用 `models.py` 中的 dataclass，字段名一致 |
| **扫描与打印分离** | 所有 `scan_*` 函数只返回数据不打印；打印由 `print_*` 函数负责 |
| **公共函数** | `parse_ports` 和 `validate_target` 统一从 `utils.py` 导入 |
| **并发** | `connect` / `syn` 内置 `ThreadPoolExecutor`；FIN 为串行 |
| **错误处理** | 所有异常在扫描器内部捕获并转为对应 status（`error`），不会向上抛出 |

---

## 三种扫描方式对比

| 特性 | TCP Connect | TCP SYN | TCP FIN |
|------|------------|---------|---------|
| **三次握手** | ✅ 完整完成 | ❌ 半开放（发 RST 中断） | ❌ 不发 SYN |
| **权限要求** | 无 | root/sudo | root/sudo |
| **隐蔽性** | ⭐（留下日志） | ⭐⭐⭐（较隐蔽） | ⭐⭐⭐⭐（最隐蔽） |
| **可靠性** | ⭐⭐⭐⭐⭐（最可靠） | ⭐⭐⭐⭐ | ⭐⭐（依赖 OS 实现） |
| **依赖库** | 标准库 | scapy | scapy |
| **绕过防火墙** | ❌ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Windows 兼容性** | ✅ 完全兼容 | ✅ 支持（需管理员） | ⚠️ 效果不佳 |
| **速度** | 快（多线程） | 快（多线程） | 较慢（需等待超时） |

---

## 注意事项

> ⚠️ **法律与道德**：请仅扫描您自己拥有或已获得明确授权的主机。未经授权的端口扫描可能违反法律法规。

1. **TCP SYN 和 FIN 扫描** 在 Linux 上需要 `sudo` 权限，Windows 上需以管理员身份运行。
2. **TCP FIN 扫描** 对 Windows 目标通常不准确，因为 Windows 的 TCP 栈不严格遵循 RFC 793。
3. **扫描结果** 仅反映目标端口状态，不判断端口上运行的具体服务。
4. 扫描函数与打印函数已分离，GUI/JSON/CSV 输出可直接使用 `scan_*` 函数返回的结果。

---

## 项目结构

```
tcp/
├── README.md                  # 本文件（含 API 文档与整合指南）
├── utils.py                   # 公共工具（parse_ports / validate_target）
├── models.py                  # 统一数据模型（三种 dataclass）
├── tcp_connect_scanner.py     # TCP Connect 扫描器（标准库）
├── tcp_syn_scanner.py         # TCP SYN 扫描器（基于 scapy）
├── tcp_fin_scanner.py         # TCP FIN 扫描器（基于 scapy）
└── examples/
    └── integration_demo.py    # 完整整合示例代码
```
