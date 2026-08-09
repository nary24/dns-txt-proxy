# 动态域名端口代理程序 (dns-txt-proxy)

## 📌 这是什么？解决什么问题？

你是否遇到过这种情况：家里的服务（比如 WireGuard、Web 服务）没有固定公网 IP，借助 **Lucky 的 STUN 内网穿透** 确实能从外面访问了，但穿透得到的公网 `IP:端口` 是**随时变化的**，无法固定，外部访问很不方便。

`dns-txt-proxy` 就是来解决这个问题的：**它把"会变的公网 IP:端口"变成"本地固定的端口"**，让你可以从任意地方用一个固定端口去访问家中服务。

- 适用于没有固定公网 IPV4 的环境，也适用于没有公网 IP 但可通过 Lucky STUN 内网穿透拿到公网端口的环境
- 支持 **多实例配置文件模式** 和 **命令行单实例模式**
- 支持 DNS TXT 记录变化后**自动切换目标**，无需人工干预
- 适合 NAT 穿透、动态端口代理等场景，如 WireGuard / OpenVPN 客户端"变向固定"服务端的 IP 与端口
- 注意：这是一个**客户端软件**，请部署在【需要异地访问服务的那一侧】

---

## 🧭 原理与链路图

```
家中/内网服务（如 WireGuard :51820）
     │ ① Lucky STUN 内网穿透
     ▼
获得公网 IP:端口（会变化，如 1.2.3.4:52301）
     │ ② Lucky 动态域名(DDNS) 写入 TXT 记录
     ▼
DNS TXT 记录  wy.example.com = 1.2.3.4:52301
     │ ③ 本工具定期解析 TXT 记录
     ▼
异地客户端（本工具）监听固定端口 localhost:9000
     │ ④ 透明转发
     ▼
访问者连接 localhost:9000 = 连接家中服务
```

上图中：

- **① ② 在"服务端"完成**：由 Lucky 的 STUN 内网穿透获取公网 `IP:端口`，再由 Lucky 动态域名(DDNS) 自动更新到 DNS TXT 记录。
- **③ ④ 是本工具（dns-txt-proxy）在"访问侧"完成**：定期解析 TXT 记录拿到最新的 `IP:端口`，在本地监听固定端口并把流量转发过去。

---

## 🏷️ 服务端 / 客户端 角色说明

| 端 | 部署位置 | 使用软件 | 职责 |
|----|----------|----------|------|
| 服务端 | 提供服务的一侧（家中/内网） | Lucky | STUN 内网穿透 + 动态域名更新 TXT 记录 |
| 客户端 | 需要访问服务的一侧（异地） | **dns-txt-proxy** | 解析 TXT 记录并固定本地端口转发 |

> 简单说：Lucky 是"把服务暴露出去并在 DNS 上登记当前 IP:端口"的那一端；dns-txt-proxy 是"读取最新 IP:端口并以固定入口访问"的那一端。

---

## 🧭 前置准备：让 Lucky 把 IP:端口 解析到 TXT

> 使用本工具前，请先确保某个域名已存在内容为 `IP:端口` 的 **DNS TXT 记录**（否则本工具无目标可转发）。

DNS TXT 记录内容必须为：
```
IP:端口
```
例如：
```
203.0.113.10:5000
```

这个 TXT 记录一般由 **Lucky 动态域名(DDNS) 任务自动写入**：

- 1、对于没有公网 IP 的环境：先用 Lucky 的 **STUN 内网穿透** 获取到对应服务的公网 `IP:端口`，再用 Lucky 动态域名把该 `IP:端口` 解析到 DNS TXT 记录
- 2、对于有动态公网 IP 的环境：直接用 Lucky 的动态域名把 `IP:端口` 写入 TXT 记录  （当然，本身有公网IP的话 也不会用此工具了）

![图片描述](images/lucky-stun规则.jpg)
![图片描述](images/lucky动态域名获取stun的ip端口.jpg)

> Lucky的具体使用方法，请参考 Lucky官方 的 STUN 穿透文档：https://lucky666.cn/docs/modules/stun

---

## 🚀 快速开始

### 1. 命令行单实例模式
python版本：3

安装依赖： `pip install -r requirements.txt`

直接指定域名和本地监听端口：
```bash
python dns-txt-proxy.py --domain example.com --local-port 9000 --protocol tcp --interval 5 --stability 1 --dns-servers 8.8.8.8 8.8.4.4
```
参数说明：
| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--domain` | 要解析的域名（该域名需存在 `IP:端口` 格式的 TXT 记录，参见"前置准备"） | 必填 |
| `--local-port` | 本地监听端口 | 必填 |
| `--protocol` | 协议类型（`tcp` 或 `udp`） | `tcp` |
| `--interval` | 检查 TXT 记录的间隔（秒） | `10` |
| `--stability` | 稳定性判断次数（连续相同解析结果的次数才更新） | `3` |
| `--dns-servers` | 自定义 DNS 服务器（空格分隔多个） | Google DNS |
| `--log-file` | 指定生成日志文件到此位置 | 非必填 |

<font color="red">如何访问服务：
  直接本地访问localhost:9000 ，则可访问到 example.com记录的ip:端口所代理的服务
</font>
---

### 2. 配置文件多实例模式
如果不传 `--domain` 参数，则自动读取配置文件（默认 `config.conf`），可同时启动多个代理实例。

> `config.conf` 已加入 `.gitignore`，不会提交到仓库。
> 首次使用可复制 `config.conf.example` 为 `config.conf` 并修改其中的域名。

配置文件示例（详见 `config.conf.example`）：
```ini
[global]
# 日志文件路径（可选，留空则只输出到终端）
#log_file = d:\dns-txt-proxy.log

[proxy1]
domain = txt1.example.com
local_port = 9001
protocol = tcp
interval = 10
stability = 3
dns_servers = 223.5.5.5 223.6.6.6

[proxy2]
domain = txt2.example.com
local_port = 9002
protocol = udp
interval = 5
stability = 2
dns_servers = 223.5.5.5 223.6.6.6
```
启动：
```bash
python dns-txt-proxy.py
```
或指定配置文件路径：
```bash
python dns-txt-proxy.py --config /path/to/config.conf
```

---

### 3. docker 方式启动（可多实例方式）
启动：
```bash
docker-compose -f docker-compose.dns-txt-proxy.yml up -d
```

配置文件示例：同上

查看日志：
```bash
docker logs -f dns-txt-proxy
```

---

### 4. Windows 图形界面模式
下载 `DNS-TXT-Proxy-Manager.exe` 直接运行（无需 Python 环境），即系统托盘后台运行。
支持图形化管理：添加/编辑/删除端口映射、启动/停止代理、实时查看日志。
可右键托盘图标设置「开机自启」。

![图形客户端](images/图形客户端.png)

打包命令（需 Python + PyInstaller）：
```bash
python windows\build_exe.py
```

---

### 5. 将脚本注册为系统服务
[各环境把脚本注册为系统服务](各环境把脚本注册为系统服务.md)

---

### ⌨️ 停止程序
在运行窗口按：
```
Ctrl + C
```
即可停止所有代理实例。

---

## ⏱ 切换延迟说明
切换到新 `IP:端口` 的时间取决于：
```
延迟 ≈ DNS TTL + interval × stability
```
- 建议将 DNS TTL 设为 30 秒或更短，以便快速更新
- 如果需要秒级切换，可设置：
  ```
  interval=5
  stability=1
  ```
  并使用权威 DNS 服务器直连

---

## 🖥 使用场景
- 运营商不给公网IPV4时：用 Lucky 的 STUN 内网穿透 + 动态域名代理 WireGuard 服务端，再用本程序在 Windows 上以固定端口连接 WireGuard 服务端
- 同上也可代理 Web 服务
- 修改一下脚本，可部署在 OpenWrt 中连接 WireGuard 服务端等

---

## 📚 参考文档
- Lucky STUN 内网穿透官方文档：https://lucky666.cn/docs/modules/stun
- Lucky 动态域名(DDNS)官方文档：https://lucky666.cn/docs/modules/ddns
- 网友教程 / 经验分享（含 STUN 内网穿透部分教程）：https://lucky666.cn/docs/shareteach/