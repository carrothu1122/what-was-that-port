# 网络端口扫描系统 (what-was-that-port)

一个基于 Python 的网络端口扫描系统，包含底层扫描引擎（TCP Connect / TCP SYN / TCP FIN / UDP / ICMP 主机探测 / 服务指纹识别）与基于 PySide6 的图形化前端，支持命令行与 GUI 两种使用方式，并支持扫描结果导出。

## 功能特性

- **主机存活探测（ICMP）**：发送 ICMP Echo Request 判断目标主机是否在线，无权限时会给出明确提示。
- **TCP Connect 扫描**：调用系统 `connect()`，无需特殊权限，支持并发、暂停/继续/取消、扫描速度模式（慢速/普通/快速/自定义并发数）与扫描统计。
- **TCP SYN 扫描**：基于 Scapy 发送 SYN 包的半开放扫描，需要 root/sudo 权限，可识别 open / closed / filtered / unreachable / unknown 等状态，并解析 ICMP 不可达信息。
- **TCP FIN 扫描**：基于 Scapy 发送 FIN 包的隐蔽扫描方式，需要 root/sudo 权限，可穿透部分仅过滤 SYN 包的防火墙/包过滤规则。
- **UDP 扫描**：基于 Scapy 发送 UDP 探针，可通过 UDP 响应、ICMP Port Unreachable 与超时区分 open / closed / open|filtered 等状态。
- **服务指纹识别**：对开放端口发送协议探针（HTTP/HTTPS/FTP/SMTP/MySQL/Redis 等）并匹配响应，推测服务名称与版本信息。
- **结果导出**：CLI 支持导出为 TXT/JSON，GUI 支持导出为 CSV。
- **统一 CLI 入口**：`python -m tcp_scanner` 提供 `scan` / `fingerprint` / `ping` 子命令，支持中英文输出。
- **图形化界面（GUI）**：基于 PySide6，提供目标输入、端口范围、扫描方式勾选（ICMP/Connect/SYN/FIN/UDP）、结果表格（按状态着色）、运行日志、进度条与 CSV 导出；高级扫描会提示授权，并只提权后台 worker，GUI 本身保持普通权限运行。

## 环境要求

- Python 3.10+
- Linux 下 TCP SYN、TCP FIN、UDP 需要原始套接字权限；GUI 会通过 `pkexec` 启动一次性后台 worker。
- Windows 下普通 TCP Connect 扫描可直接运行；TCP SYN、TCP FIN、UDP 需要管理员权限，且通常需要安装 Npcap 才能让 Scapy 使用底层抓包/发包能力。

## 安装

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

开发安装也可以使用：

```bash
pip install -e .
```

## 使用方式

### 命令行（CLI）

```bash
# 开发安装后可使用统一 CLI
what-was-that-port-cli scan 127.0.0.1 -p 22,80,443 --mode connect

# TCP Connect 扫描（默认模式，无需 sudo）
python cli.py scan 127.0.0.1 -p 22,80,443 --mode connect

# TCP SYN 扫描（需要 sudo）
sudo python cli.py scan 127.0.0.1 -p 1-1024 --mode syn

# TCP FIN 扫描（需要 sudo）
sudo python cli.py scan 127.0.0.1 -p 21,22,80 --mode fin

# UDP 扫描（需要 sudo；无响应会显示 open|filtered）
sudo python cli.py scan 127.0.0.1 -p 53,123,161 --mode udp

# 服务指纹识别
python cli.py fingerprint 127.0.0.1 -p 22,80,443

# ICMP 主机存活探测
python cli.py ping 127.0.0.1

# 输出前端可用的 JSON，并导出结果
python cli.py scan 127.0.0.1 -p 1-1024 --mode connect --json --export-results --export-dir ./output
```

### 图形界面（GUI）

```bash
# 开发安装后
what-was-that-port

# 或直接从源码运行
python main1.py
```

界面支持：目标 IP 输入、起止端口设置、勾选 ICMP/TCP Connect/TCP SYN/TCP FIN/UDP、开始扫描、清空结果、导出 CSV。勾选 TCP SYN、TCP FIN 或 UDP 时，GUI 会提示是否授权本次高级扫描；用户也可以选择只运行 TCP Connect / ICMP 等普通扫描。

高级扫描权限结构：

```
main1.py 普通权限 GUI
        |
        | request/result JSON 文件
        v
privileged_worker.py 授权子进程
        |
        +-- TCP SYN
        +-- TCP FIN
        +-- UDP
```

打包相关说明见 `packaging/README.md`。当前项目已经提供开发安装入口：

- `what-was-that-port`
- `what-was-that-port-cli`
- `what-was-that-port-worker`

## 项目结构

```
.
├── cli.py                    # 统一命令行入口（scan / fingerprint / ping）
├── main1.py                   # PySide6 图形界面
├── scanner_adapter.py          # GUI 与底层扫描模块之间的适配层
├── privilege_adapter.py        # Linux pkexec / Windows UAC 权限适配层
├── privileged_worker.py        # 高级扫描授权后台 worker
├── models.py                   # 各扫描器的统一结果数据结构
├── utils.py                    # IP/端口校验与解析等公共工具函数
├── host_discovery.py           # ICMP 主机存活探测
├── tcp_connect_scanner.py      # TCP Connect 扫描器（含并发/暂停/统计）
├── tcp_syn_scanner.py          # TCP SYN 扫描器（基于 Scapy）
├── tcp_fin_scanner.py          # TCP FIN 扫描器（基于 Scapy）
├── udp_scanner.py              # UDP 扫描器（基于 Scapy）
├── service_fingerprint.py      # 服务指纹识别
├── fingerprints.py             # 服务指纹探针与匹配规则库
├── examples/integration_demo.py # 三种扫描器整合调用示例
└── requirements.txt
```

## 免责声明

本工具仅用于学习交流与安全测试目的，请仅对自己拥有或已获得明确授权的主机和网络进行扫描。未经授权对他人网络设备进行扫描可能违反当地法律法规，使用者需自行承担相应责任。
