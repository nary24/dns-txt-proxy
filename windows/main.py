import sys
import os
import threading
import time
import logging
import winreg

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from windows.log_handler import RingBufferHandler
from windows.proxy_manager import ProxyManager
from windows.gui.main_window import MainWindow
from windows import settings

AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME = "DNS-TXT-Proxy-Manager"


def _is_frozen():
    return getattr(sys, 'frozen', False)


def _autostart_is_enabled() -> bool:
    if not _is_frozen():
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0,
                            winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, AUTOSTART_NAME)
            return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def _autostart_set(enable: bool) -> bool:
    if not _is_frozen():
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            if enable:
                winreg.SetValueEx(key, AUTOSTART_NAME, 0, winreg.REG_SZ,
                                  sys.executable)
            else:
                try:
                    winreg.DeleteValue(key, AUTOSTART_NAME)
                except FileNotFoundError:
                    pass
            return True
    except Exception as e:
        logging.getLogger(__name__).error(f"设置开机自启失败: {e}")
        return False


def _create_tray_image():
    from PIL import Image, ImageDraw
    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([2, 2, 62, 62], fill='#1976D2')
    draw.ellipse([10, 10, 54, 54], fill='#1565C0')
    draw.text((20, 16), "DNS", fill='white')
    return img


def _make_autostart_text(item=None):
    return "✓ 开机自启" if _autostart_is_enabled() else "  开机自启"


def _toggle_autostart(icon, item):
    enabled = not _autostart_is_enabled()
    if _autostart_set(enabled):
        icon.update_menu()


def main():
    log_handler = RingBufferHandler()
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        '[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    log_handler.setFormatter(fmt)
    root_logger.addHandler(log_handler)

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root_logger.addHandler(console)

    logger = logging.getLogger(__name__)

    custom_cfg = settings.get_custom_config_path()
    if custom_cfg:
        logger.info(f"使用自定义配置: {custom_cfg}")

    manager = ProxyManager(config_path=custom_cfg or None)
    proxies = manager.load_config()
    logger.info(f"已加载 {len(proxies)} 个代理配置")

    def on_config_change(path):
        logger.info(f"配置文件已切换: {path}")

    window = MainWindow(manager, log_handler,
                        on_config_change=on_config_change)

    try:
        import pystray
        from pystray import MenuItem as Item

        def on_show(icon, item):
            window.after(0, window.deiconify)
            window.after(0, window.lift)

        def on_exit(icon, item):
            icon.stop()
            window.after(0, window.quit)

        items = [
            Item("显示管理窗口", on_show, default=True),
            pystray.Menu.SEPARATOR,
        ]
        if _is_frozen():
            items.append(
                Item(_make_autostart_text, _toggle_autostart,
                     checked=lambda item: _autostart_is_enabled())
            )
            items.append(pystray.Menu.SEPARATOR)
        items.append(Item("退出", on_exit))

        menu = pystray.Menu(*items)

        icon = pystray.Icon(
            "dns-txt-proxy", _create_tray_image(),
            "DNS TXT Proxy", menu
        )

        t = threading.Thread(target=icon.run, daemon=True)
        t.start()
        logger.info("系统托盘已启动")
    except ImportError:
        logger.warning("pystray 未安装，直接显示窗口")
        window.deiconify()

    window.mainloop()

    logger.info("正在停止所有代理...")
    manager.stop_all()
    time.sleep(1)
    logger.info("程序已退出")


if __name__ == "__main__":
    main()
