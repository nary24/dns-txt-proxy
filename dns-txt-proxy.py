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
from typing import Optional, Tuple, List, Dict
import configparser
import sys

SocketAddress = Tuple[str, int]
UDPClientMap = Dict[SocketAddress, float]

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class DynamicProxy:
    def __init__(self, domain: str, local_port: int, protocol: str = 'tcp',
                 check_interval: int = 10, udp_buffer_size: int = 4096,
                 dns_timeout: int = 5, stability_threshold: int = 3,
                 dns_servers: Optional[List[str]] = None):
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
            self.resolver.cache = None  # type: ignore
        except AttributeError:
            pass

    def resolve_txt(self) -> Optional[SocketAddress]:
        try:
            answers = self.resolver.resolve(self.domain, 'TXT', lifetime=self.dns_timeout)
            for ans in answers:
                txt_data = ans.to_text().strip('"')
                if ':' in txt_data:
                    ip, port_str = txt_data.split(':', 1)
                    if ip and port_str.isdigit():
                        return (ip, int(port_str))
            logging.warning(f"域名 {self.domain} 的TXT记录格式不正确")
            return None
        except dns.resolver.NXDOMAIN:
            logging.warning(f"域名 {self.domain} 不存在")
            return None
        except dns.resolver.Timeout:
            logging.warning(f"解析域名 {self.domain} 超时")
            return None
        except Exception as e:
            logging.warning(f"TXT记录解析失败: {str(e)}")
            return None

    def check_update(self, is_initial_check: bool = False) -> None:
        if is_initial_check:
            logging.info(f"启动时检查 {self.domain} 的TXT记录...")
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
                    logging.debug(f"解析结果不稳定: {list(self.recent_resolutions)}")
        else:
            self.recent_resolutions.clear()

    def _update_target_if_needed(self, new_target: SocketAddress, is_initial_check: bool = False) -> None:
        if new_target != self.target:
            old_target = self.target
            self.target = new_target
            if is_initial_check:
                logging.info(f"初始目标: {self.target[0]}:{self.target[1]}")
            else:
                logging.info(f"目标更新: {old_target} -> {self.target[0]}:{self.target[1]}")
            self._recreate_udp_socket()

    def _recreate_udp_socket(self) -> None:
        if self.udp_target_socket and self.protocol == 'udp':
            try:
                self.udp_target_socket.close()
            except:
                pass
            time.sleep(0.1)
            self.udp_target_socket = self.create_udp_socket()
            logging.info("已重建UDP目标socket")

    def create_udp_socket(self) -> socket.socket:
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
            logging.error(f"TCP代理错误: {str(e)}")
        finally:
            client_socket.close()
            if target_socket:
                target_socket.close()

    def udp_client_listener(self) -> None:
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
                self._handle_udp_exception(e, "客户端监听")

    def udp_target_listener(self) -> None:
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
                self._handle_udp_exception(e, "目标监听")

    def _handle_udp_exception(self, e: Exception, context: str) -> None:
        if self.is_windows:
            error_code = str(e).split('[')[-1].split(']')[0] if '[' in str(e) else ''
            if error_code in ["10022", "10038", "10054"]:
                logging.warning(f"Windows UDP{context}错误 {error_code}: 重建socket...")
                self._recreate_udp_socket()
                return
        logging.error(f"UDP{context}错误: {str(e)}")
        time.sleep(1)

    def _find_recent_client(self) -> Optional[SocketAddress]:
        current_time = time.time()
        for addr, last_active in self.client_map.items():
            if current_time - last_active < 30:
                return addr
        return None

    def udp_proxy_handler(self) -> None:
        self.udp_target_socket = self.create_udp_socket()
        client_thread = threading.Thread(target=self.udp_client_listener, daemon=True)
        target_thread = threading.Thread(target=self.udp_target_listener, daemon=True)
        client_thread.start()
        target_thread.start()
        self._cleanup_expired_clients()
        if self.udp_target_socket:
            try:
                self.udp_target_socket.close()
            except:
                pass

    def _cleanup_expired_clients(self) -> None:
        while self.running:
            current_time = time.time()
            for addr in list(self.client_map.keys()):
                if current_time - self.client_map[addr] > 30:
                    del self.client_map[addr]
            time.sleep(5)

    def start_server(self) -> None:
        try:
            socket_type = socket.SOCK_STREAM if self.protocol == 'tcp' else socket.SOCK_DGRAM
            self.server_socket = socket.socket(socket.AF_INET, socket_type)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.is_windows and self.protocol == 'udp':
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.server_socket.bind(('0.0.0.0', self.local_port))
            logging.info(f"{self.protocol.upper()}代理已启动，监听本地端口 {self.local_port}")
            if self.protocol == 'tcp':
                self._start_tcp_server()
            else:
                self.udp_proxy_handler()
        except Exception as e:
            logging.error(f"服务器启动错误: {str(e)}")
            self.running = False

    def _start_tcp_server(self) -> None:
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
        self.running = True
        self.check_update(is_initial_check=True)
        server_thread = threading.Thread(target=self.start_server, daemon=True)
        server_thread.start()
        try:
            while self.running:
                time.sleep(self.check_interval)
                self.check_update()
        except KeyboardInterrupt:
            logging.info("\n用户中断，程序正在退出...")
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
    config = configparser.ConfigParser()
    config.read(config_file, encoding="utf-8")
    proxies = []
    for section in config.sections():
        domain = config.get(section, "domain")
        local_port = config.getint(section, "local_port")
        protocol = config.get(section, "protocol", fallback="tcp")
        interval = config.getint(section, "interval", fallback=10)
        stability = config.getint(section, "stability", fallback=3)
        dns_servers = config.get(section, "dns_servers", fallback="")
        dns_servers_list = dns_servers.split() if dns_servers else None

        proxy = DynamicProxy(domain, local_port, protocol, interval,
                             stability_threshold=stability,
                             dns_servers=dns_servers_list)
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
    parser = argparse.ArgumentParser(description='稳定版动态域名代理程序')
    parser.add_argument('--domain', help='要解析的域名')
    parser.add_argument('--local-port', type=int, help='本地监听端口')
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp', help='代理协议')
    parser.add_argument('--interval', type=int, default=10, help='TXT记录定期检查间隔（秒）')
    parser.add_argument('--stability', type=int, default=3, help='地址稳定判断次数（默认3次）')
    parser.add_argument('--dns-servers', nargs='*', help='DNS服务器IP列表')
    parser.add_argument('--config', help='配置文件路径（未指定domain时使用）', default="config.conf")
    args = parser.parse_args()

    if args.domain and args.local_port:
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
