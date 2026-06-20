import importlib.util
import os
import sys
import threading
import time
import configparser
import logging
import logging.handlers
from typing import Optional, List, Dict, Any

_core_module = None


def _get_base_path() -> str:
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(__file__))


def _get_core():
    global _core_module
    if _core_module is not None:
        return _core_module
    core_path = os.path.join(_get_base_path(), "dns-txt-proxy.py")
    spec = importlib.util.spec_from_file_location("dns_txt_proxy_core", core_path)
    _core_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_core_module)
    return _core_module


def _get_config_path(custom_path: Optional[str] = None) -> str:
    if custom_path:
        return custom_path
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        local_conf = os.path.join(exe_dir, "config.conf")
        if not os.path.exists(local_conf):
            bundled = os.path.join(_get_base_path(), "config.conf")
            if os.path.exists(bundled):
                import shutil
                try:
                    shutil.copy2(bundled, local_conf)
                except Exception:
                    pass
        return local_conf
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.conf")


class ProxyManager:
    def __init__(self, config_path: Optional[str] = None):
        self._config_path = _get_config_path(config_path)
        self._proxies: Dict[str, Any] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        self._logger = logging.getLogger(__name__)
        self._core = _get_core()

    @property
    def config_path(self) -> str:
        return self._config_path

    def _read_config(self) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config.read(self._config_path, encoding="utf-8")
        return config

    def _write_config(self, config: configparser.ConfigParser) -> None:
        with open(self._config_path, 'w', encoding='utf-8') as f:
            config.write(f)

    def _create_proxy(self, name: str, section_data: dict) -> Any:
        DynamicProxy = self._core.DynamicProxy
        SectionLoggerAdapter = self._core.SectionLoggerAdapter
        logger = SectionLoggerAdapter(
            logging.getLogger(__name__), {"section": name}
        )

        dns_str = section_data.get('dns_servers', '')
        dns_servers_list = dns_str.split() if dns_str else None

        proxy = DynamicProxy(
            domain=section_data['domain'],
            local_port=int(section_data['local_port']),
            protocol=section_data.get('protocol', 'tcp'),
            check_interval=int(section_data.get('interval', 10)),
            stability_threshold=int(section_data.get('stability', 3)),
            dns_servers=dns_servers_list,
            logger=logger,
            section=name
        )
        return proxy

    def _start_proxy_internal(self, name: str, proxy: Any) -> bool:
        with self._lock:
            if name in self._proxies:
                return False
            self._proxies[name] = proxy
            t = threading.Thread(
                target=proxy.start, daemon=True, name=f"proxy-{name}"
            )
            t.start()
            self._threads[name] = t
        return True

    def load_config(self) -> List[tuple]:
        config = self._read_config()
        started = []
        for section in config.sections():
            if section == "global":
                continue
            try:
                data = {
                    'domain': config.get(section, 'domain'),
                    'local_port': config.getint(section, 'local_port'),
                    'protocol': config.get(section, 'protocol', fallback='tcp'),
                    'interval': config.getint(section, 'interval', fallback=10),
                    'stability': config.getint(section, 'stability', fallback=3),
                    'dns_servers': config.get(section, 'dns_servers', fallback=''),
                }
                proxy = self._create_proxy(section, data)
                self._start_proxy_internal(section, proxy)
                started.append((section, data))
            except Exception as e:
                self._logger.error(f"加载代理 [{section}] 失败: {e}")
        return started

    def add_proxy(self, name: str, data: dict) -> None:
        if name in self._proxies:
            raise ValueError(f"代理 '{name}' 已存在")

        config = self._read_config()
        config[name] = {
            'domain': data['domain'],
            'local_port': str(data['local_port']),
            'protocol': data.get('protocol', 'tcp'),
            'interval': str(data.get('interval', 10)),
            'stability': str(data.get('stability', 3)),
        }
        if data.get('dns_servers'):
            config[name]['dns_servers'] = data['dns_servers']
        self._write_config(config)

        proxy = self._create_proxy(name, data)
        self._start_proxy_internal(name, proxy)

    def remove_proxy(self, name: str) -> None:
        with self._lock:
            proxy = self._proxies.pop(name, None)
            self._threads.pop(name, None)
        if proxy:
            self._force_stop(proxy)

        config = self._read_config()
        if config.has_section(name):
            config.remove_section(name)
        self._write_config(config)

    def _force_stop(self, proxy) -> None:
        proxy.running = False
        try:
            if proxy.server_socket:
                proxy.server_socket.close()
        except Exception:
            pass
        try:
            if proxy.udp_target_socket:
                proxy.udp_target_socket.close()
        except Exception:
            pass

    def update_proxy(self, old_name: str, data: dict) -> None:
        new_name = data.get('name', old_name)
        with self._lock:
            proxy = self._proxies.pop(old_name, None)
            self._threads.pop(old_name, None)
        if proxy:
            self._force_stop(proxy)

        config = self._read_config()
        if config.has_section(old_name):
            config.remove_section(old_name)
        if config.has_section(new_name) and new_name != old_name:
            config.remove_section(new_name)
        config[new_name] = {
            'domain': data['domain'],
            'local_port': str(data['local_port']),
            'protocol': data.get('protocol', 'tcp'),
            'interval': str(data.get('interval', 10)),
            'stability': str(data.get('stability', 3)),
        }
        if data.get('dns_servers'):
            config[new_name]['dns_servers'] = data['dns_servers']
        self._write_config(config)

        proxy = self._create_proxy(new_name, data)
        self._start_proxy_internal(new_name, proxy)

    def stop_proxy(self, name: str) -> None:
        with self._lock:
            self._threads.pop(name, None)
            proxy = self._proxies.get(name)
        if proxy:
            self._force_stop(proxy)

    def start_proxy(self, name: str) -> None:
        with self._lock:
            existing = self._proxies.get(name)
            if existing and existing.running:
                self._logger.warning(f"代理 '{name}' 已在运行中")
                return
            old = self._proxies.pop(name, None)
            self._threads.pop(name, None)
        if old:
            self._force_stop(old)

        config = self._read_config()
        if not config.has_section(name):
            self._logger.error(f"配置中找不到代理 '{name}'")
            return
        data = {
            'domain': config.get(name, 'domain'),
            'local_port': config.getint(name, 'local_port'),
            'protocol': config.get(name, 'protocol', fallback='tcp'),
            'interval': config.getint(name, 'interval', fallback=10),
            'stability': config.getint(name, 'stability', fallback=3),
            'dns_servers': config.get(name, 'dns_servers', fallback=''),
        }
        proxy = self._create_proxy(name, data)
        self._start_proxy_internal(name, proxy)

    def stop_all(self) -> None:
        with self._lock:
            names = list(self._proxies.keys())
        for name in names:
            self.stop_proxy(name)

    def set_config_path(self, path: str) -> None:
        self._config_path = path

    def reload_config(self) -> List[tuple]:
        self.stop_all()
        with self._lock:
            self._proxies.clear()
            self._threads.clear()
        time.sleep(0.5)
        return self.load_config()

    def get_config_path(self) -> str:
        return self._config_path

    def get_status_list(self) -> List[Dict[str, Any]]:
        statuses = []
        with self._lock:
            for name, proxy in self._proxies.items():
                statuses.append({
                    'name': name,
                    'domain': proxy.domain,
                    'local_port': proxy.local_port,
                    'protocol': proxy.protocol.upper(),
                    'running': proxy.running,
                    'target': (
                        f"{proxy.target[0]}:{proxy.target[1]}"
                        if proxy.target else "等待解析..."
                    ),
                })
        return statuses

    def is_running(self, name: str) -> bool:
        with self._lock:
            proxy = self._proxies.get(name)
            return proxy is not None and proxy.running
