DNS TXT Proxy - Windows 图形客户端
====================================

快速使用
--------
直接下载 DNS-TXT-Proxy-Manager.exe 运行即可（无需安装 Python）。

如需从源码运行或打包：

1. 安装依赖：
   pip install -r windows\requirements.txt

2. 运行：
   python windows\main.py

3. 打包成单 exe：
   pip install pyinstaller
   python windows\build_exe.py
   产出：dist\DNS-TXT-Proxy-Manager.exe

功能说明
--------
- 系统托盘后台常驻（桌面右下角图标）
- 添加/编辑/删除端口映射（支持名称、域名、端口、协议、DNS 服务器等配置）
- 启动/停止单个映射（▶/⏹ 按钮）或批量重载
- 实时状态显示：每 3 秒自动刷新运行状态和目标解析 IP
- 手动刷新：修改 config.conf 后点击工具栏「⟳ 刷新」重载所有代理（不会自动检测变更）
- 切换配置文件：点击「📁 配置文件」可选择其他目录的 config.conf
- 开机自启：右键托盘图标切换「开机自启」
- 实时日志查看（支持按文本过滤、自动滚动）
- 配置自动保存至 config.conf（兼容命令行模式）

注册为 Windows 服务（推荐使用图形界面）
-----------------------------------------------
推荐直接运行 DNS-TXT-Proxy-Manager.exe 并开启「开机自启」即可实现后台运行，
无需额外注册为 Windows 服务。

如需注册为 Windows 服务（使用 nssm）：

1. 下载 nssm：https://nssm.cc/download
2. 管理员终端运行：
   nssm install DNS-TXT-Proxy "C:\path\to\python.exe"
   "C:\path\to\dns-txt-proxy\windows\main.py"
3. 或使用命令行模式（无需 GUI）：
   nssm install DNS-TXT-Proxy-CLI "C:\path\to\python.exe"
   "C:\path\to\dns-txt-proxy\dns-txt-proxy.py" --config "C:\path\to\config.conf"

注意
----
- 首次运行 exe 会自动将内置 config.conf 拷贝到 exe 所在目录
- 图形界面与命令行模式（dns-txt-proxy.py --config config.conf）共享同一配置文件，互不冲突
- 原 dns-txt-proxy.py 完全未修改，命令行启动不受影响
- Python 3.14.6 + Windows 11 下开发测试
