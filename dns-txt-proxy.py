#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import time
import dns.resolver
import argparse
import select
import os
from collections import deque
import logging
from logging.handlers import TimedRotatingFileHandler
from typing import Optional, Tuple, List, Dict
import configparser
import sys

SocketAddress = Tuple[str, int]
UDPClientMap = Dict[SocketAddress, float]

def get_log_path(log_file: Optional[str]) -> Optional[str]:
    """获取日志文件路径"""
    if log_file:
        return log_file
    return None  # 不指定则返回 None，表示不写文件

def setup_logging(log_path: Optional[str]):
    """统一初始化日志，支持按天分割，不指定路径则只输出到终端"""
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    handlers = [logging.StreamHandler()]
    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        file_handler = TimedRotatingFileHandler(
            log_path, when="midnight", interval=1, backupCount=7, encoding="utf-8"
        )
        file_handler.suffix = "%Y-%m-%d"
        handlers.append(file_handler)

    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers
    )

class SectionLoggerAdapter(logging.LoggerAdapter):
    """给日志加 [section] 前缀"""
    def process(self, msg, kwargs):
        return f"[{self.extra['section']}] {msg}", kwargs

class DynamicProxy:
    def __init__(self, domain: str, local_port: int, protocol: str = 'tcp',
                 check_interval: int = 10, udp_buffer_size: int = 4096,
                 dns_timeout: int = 5, stability_threshold: int = 3,
                 dns_servers: Optional[List[str]] = None,
                 logger: Optional[logging.Logger] = None,
                 section: str = "main"):
        """
        初始化 DynamicProxy 实例

        :param domain: 要解析的域名
        :param local_port: 本地监听端口
        :param protocol: 代理协议 ('tcp' 或 'udp')
        :param check_interval: TXT记录定期检查间隔（秒）
        :param udp_buffer_size: UDP缓冲区大小
        :param dns_timeout: DNS解析超时时间（秒）
        :param stability_threshold: 地址稳定判断次数
        :param dns_servers: DNS服务器IP列表
        :param logger: 日志记录器
        :param section: 配置节名称
        """
        self.domain = domain
        self.local_port = local_port
        self.protocol = protocol.lower()
        self.check_interval = check_interval
        self.udp_buffer_size = udp_buffer_size
        self.target: Optional[SocketAddress] = None
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.client_map: UDPClientMap = {}
        self.is_windows = os.name == 'nt'
        self.udp_target_socket: Optional[socket.socket] = None
        self.dns_timeout = dns_timeout
        self.stability_threshold = max(1, stability_threshold)
        self.logger = logger or logging.getLogger(__name__)
        self.section = section

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.dns_timeout
        self.resolver.lifetime = self.dns_timeout
        if dns_servers:
            self.resolver.nameservers = dns_servers
        else:
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']

        self.recent_resolutions: deque[SocketAddress] = deque(
            maxlen=self.stability_threshold
        )
        try:
            self.resolver.cache = None
        except AttributeError:
            pass

    def resolve_txt(self) -> Optional[SocketAddress]:
        """
        解析域名的TXT记录，提取目标IP和端口

        :return: 解析成功返回 (IP, 端口) 元组，失败返回 None
        """
        try:
            answers = self.resolver.resolve(self.domain, 'TXT', lifetime=self.dns_timeout)
            for ans in answers:
                txt_data = ans.to_text().strip('"')
                if ':' in txt_data:
                    ip, port_str = txt_data.split(':', 1)
                    if ip and port_str.isdigit():
                        return (ip, int(port_str))
            self.logger.warning(f"{self.domain} TXT记录格式不正确")
            return None
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"{self.domain} 域名不存在")
            return None
        except dns.resolver.Timeout:
            self.logger.warning(f"{self.domain} 解析超时")
            return None
        except Exception as e:
            self.logger.warning(f"{self.domain} TXT记录解析失败: {str(e)}")
            return None

    def check_update(self, is_initial_check: bool = False) -> None:
        """
        检查并更新目标地址

        :param is_initial_check: 是否为初始检查
        """
        if is_initial_check:
            self.logger.info(f"启动时检查 {self.domain} TXT记录...")
        new_target = self.resolve_txt()

        if new_target:
            self.recent_resolutions.append(new_target)
            if is_initial_check:
                self._update_target_if_needed(new_target, is_initial_check)
                return
            if self.stability_threshold == 1:
                self._update_target_if_needed(new_target)
                return
            if len(self.recent_resolutions) == self.stability_threshold:
                if all(addr == new_target for addr in self.recent_resolutions):
                    self._update_target_if_needed(new_target)
        else:
            self.recent_resolutions.clear()

    def _update_target_if_needed(self, new_target: SocketAddress, is_initial_check: bool = False) -> None:
        """
        检查并更新目标地址

        :param is_initial_check: 是否为初始检查
        """
        if new_target != self.target:
            old_target = self.target
            self.target = new_target
            if is_initial_check:
                self.logger.info(f"{self.domain} 初始目标: {self.target[0]}:{self.target[1]}")
            else:
                self.logger.info(f"{self.domain} 目标更新: {old_target} -> {self.target[0]}:{self.target[1]}")
            self._recreate_udp_socket()

    def _recreate_udp_socket(self) -> None:
        """重新创建UDP目标套接字"""
        if self.udp_target_socket and self.protocol == 'udp':
            try:
                self.udp_target_socket.close()
            except:
                pass
            time.sleep(0.1)
            self.udp_target_socket = self.create_udp_socket()
            self.logger.info("已重建UDP目标socket")

    def create_udp_socket(self) -> socket.socket:
        """
        创建UDP套接字

        :return: 创建的UDP套接字
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.is_windows:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.bind(('0.0.0.0', 0))
            except:
                pass
        sock.settimeout(1.0)
        return sock

    def tcp_proxy_handler(self, client_socket: socket.socket) -> None:
        """
        处理TCP代理连接

        :param client_socket: 客户端套接字
        """
        if not self.target:
            client_socket.close()
            return
        target_socket: Optional[socket.socket] = None
        try:
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect(self.target)
            sockets = [client_socket, target_socket]
            while True:
                readable, _, _ = select.select(sockets, [], [], 5)
                if not readable:
                    break
                for sock in readable:
                    data = sock.recv(4096)
                    if not data:
                        return
                    other_sock = target_socket if sock is client_socket else client_socket
                    other_sock.sendall(data)
        except Exception as e:
            self.logger.error(f"{self.domain} TCP代理错误: {str(e)}")
        finally:
            client_socket.close()
            if target_socket:
                target_socket.close()

    def udp_client_listener(self) -> None:
        """监听UDP客户端数据包"""
        while self.running:
            if not self.target or not self.udp_target_socket or not self.server_socket:
                time.sleep(1)
                continue
            try:
                ready_to_read, _, _ = select.select([self.server_socket], [], [], 1)
                if not ready_to_read:
                    continue
                data, client_addr = self.server_socket.recvfrom(self.udp_buffer_size)
                if not data:
                    continue
                self.client_map[client_addr] = time.time()
                self.udp_target_socket.sendto(data, self.target)
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"{self.domain} UDP客户端监听错误: {str(e)}")

    def udp_target_listener(self) -> None:
        """监听UDP客户端数据包"""
        while self.running:
            if not self.target or not self.udp_target_socket or not self.server_socket:
                time.sleep(1)
                continue
            try:
                ready_to_read, _, _ = select.select([self.udp_target_socket], [], [], 1)
                if not ready_to_read:
                    continue
                data, _ = self.udp_target_socket.recvfrom(self.udp_buffer_size)
                if not data:
                    continue
                client_addr = self._find_recent_client()
                if client_addr:
                    self.server_socket.sendto(data, client_addr)
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"{self.domain} UDP目标监听错误: {str(e)}")

    def _find_recent_client(self) -> Optional[SocketAddress]:
        """
        查找最近活跃的客户端地址

        :return: 最近活跃的客户端地址，如果没有则返回 None
        """
        current_time = time.time()
        for addr, last_active in self.client_map.items():
            if current_time - last_active < 30:
                return addr
        return None

    def udp_proxy_handler(self) -> None:
        """
        查找最近活跃的客户端地址

        :return: 最近活跃的客户端地址，如果没有则返回 None
        """
        self.udp_target_socket = self.create_udp_socket()
        threading.Thread(target=self.udp_client_listener, daemon=True).start()
        threading.Thread(target=self.udp_target_listener, daemon=True).start()
        self._cleanup_expired_clients()

    def _cleanup_expired_clients(self) -> None:
        """清理过期的客户端记录"""
        while self.running:
            current_time = time.time()
            for addr in list(self.client_map.keys()):
                if current_time - self.client_map[addr] > 30:
                    del self.client_map[addr]
            time.sleep(5)

    def start_server(self) -> None:
        """启动服务"""
        try:
            socket_type = socket.SOCK_STREAM if self.protocol == 'tcp' else socket.SOCK_DGRAM
            self.server_socket = socket.socket(socket.AF_INET, socket_type)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.is_windows and self.protocol == 'udp':
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.server_socket.bind(('0.0.0.0', self.local_port))
            self.logger.info(f"{self.domain} {self.protocol.upper()}代理已启动，监听端口 {self.local_port}")
            if self.protocol == 'tcp':
                self._start_tcp_server()
            else:
                self.udp_proxy_handler()
        except Exception as e:
            self.logger.error(f"{self.domain} 服务器启动错误: {str(e)}")
            self.running = False

    def _start_tcp_server(self) -> None:
        """启动TCP服务器"""
        if not self.server_socket:
            return
        self.server_socket.listen(5)
        while self.running:
            try:
                self.server_socket.settimeout(1)
                client_socket, _ = self.server_socket.accept()
                threading.Thread(
                    target=self.tcp_proxy_handler,
                    args=(client_socket,),
                    daemon=True
                ).start()
            except socket.timeout:
                continue

    def start(self) -> None:
        """启动TCP服务器"""
        self.running = True
        self.check_update(is_initial_check=True)
        threading.Thread(target=self.start_server, daemon=True).start()
        try:
            while self.running:
                time.sleep(self.check_interval)
                self.check_update()
        except KeyboardInterrupt:
            self.logger.info(f"{self.domain} 用户中断，正在退出...")
        finally:
            self.running = False
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
            if self.udp_target_socket:
                try:
                    self.udp_target_socket.close()
                except:
                    pass


def load_config_and_start(config_file: str):
    """
    加载配置文件并启动代理服务

    :param config_file: 配置文件路径
    """
    config = configparser.ConfigParser()
    config.read(config_file, encoding="utf-8")

    log_file = None
    if config.has_section("global") and config.has_option("global", "log_file"):
        log_file = config.get("global", "log_file").strip()
    log_path = get_log_path(log_file)
    setup_logging(log_path)

    proxies = []
    for section in config.sections():
        if section == "global":
            continue
        domain = config.get(section, "domain")
        local_port = config.getint(section, "local_port")
        protocol = config.get(section, "protocol", fallback="tcp")
        interval = config.getint(section, "interval", fallback=10)
        stability = config.getint(section, "stability", fallback=3)
        dns_servers = config.get(section, "dns_servers", fallback="")
        dns_servers_list = dns_servers.split() if dns_servers else None

        section_logger = SectionLoggerAdapter(logging.getLogger(__name__), {"section": section})

        proxy = DynamicProxy(domain, local_port, protocol, interval,
                             stability_threshold=stability,
                             dns_servers=dns_servers_list,
                             logger=section_logger,
                             section=section)
        proxies.append(proxy)
        threading.Thread(target=proxy.start, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("检测到 Ctrl+C，正在停止所有代理...")
        for p in proxies:
            p.running = False
        time.sleep(1)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='dns-txt-proxy 稳定版动态域名代理程序')
    parser.add_argument('--domain', help='要解析的域名')
    parser.add_argument('--local-port', type=int, help='本地监听端口')
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp', help='代理协议')
    parser.add_argument('--interval', type=int, default=10, help='TXT记录定期检查间隔（秒）')
    parser.add_argument('--stability', type=int, default=3, help='地址稳定判断次数（默认3次）')
    parser.add_argument('--dns-servers', nargs='*', help='DNS服务器IP列表')
    parser.add_argument('--config', help='配置文件路径（未指定domain时使用）', default="config.conf")
    parser.add_argument('--log-file', help='日志文件路径（可选）')

    args = parser.parse_args()

    if args.domain and args.local_port:
        log_path = get_log_path(args.log_file)
        setup_logging(log_path)
        proxy = DynamicProxy(
            domain=args.domain,
            local_port=args.local_port,
            protocol=args.protocol,
            check_interval=args.interval,
            stability_threshold=args.stability,
            dns_servers=args.dns_servers
        )
        proxy.start()
    else:
        if not os.path.exists(args.config):
            logging.error(f"未提供参数且找不到配置文件 {args.config}")
            sys.exit(1)
        load_config_and_start(args.config)
