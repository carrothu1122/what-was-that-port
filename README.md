# 前端界面说明

本目录为网络端口扫描系统的图形化用户界面部分，采用 Python + PySide6 实现。

## 功能

- 目标 IP 输入
- 起始端口与结束端口输入
- ICMP、TCP Connect、TCP SYN、TCP FIN 扫描方式选择
- 扫描结果表格显示
- 运行日志显示
- CSV 结果导出
- 端口状态颜色区分

## 运行方式

在仓库根目录执行：

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python frontend/main1.py
