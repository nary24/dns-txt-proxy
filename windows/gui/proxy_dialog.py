import tkinter.messagebox as mb
import customtkinter as ctk
from typing import Optional


class ProxyDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="添加端口映射",
                 data: Optional[dict] = None):
        super().__init__(parent)
        self.title(title)
        self.geometry("480x420")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.result: Optional[dict] = None
        self._data = data or {}

        self._build_ui()
        if data:
            self._load_data(data)

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)

        row = 0
        ctk.CTkLabel(self, text="名称：", anchor="w").grid(
            row=row, column=0, padx=(20, 5), pady=(20, 8), sticky="w"
        )
        self.name_entry = ctk.CTkEntry(self)
        self.name_entry.grid(row=row, column=1, padx=(0, 20), pady=(20, 8), sticky="ew")

        row = 1
        ctk.CTkLabel(self, text="域名：", anchor="w").grid(
            row=row, column=0, padx=(20, 5), pady=8, sticky="w"
        )
        self.domain_entry = ctk.CTkEntry(self)
        self.domain_entry.grid(row=row, column=1, padx=(0, 20), pady=8, sticky="ew")

        row = 2
        ctk.CTkLabel(self, text="本地端口：", anchor="w").grid(
            row=row, column=0, padx=(20, 5), pady=8, sticky="w"
        )
        self.port_entry = ctk.CTkEntry(self)
        self.port_entry.grid(row=row, column=1, padx=(0, 20), pady=8, sticky="ew")

        row = 3
        ctk.CTkLabel(self, text="协议：", anchor="w").grid(
            row=row, column=0, padx=(20, 5), pady=8, sticky="w"
        )
        self.protocol_var = ctk.StringVar(value="tcp")
        self.protocol_menu = ctk.CTkOptionMenu(
            self, values=["tcp", "udp"], variable=self.protocol_var
        )
        self.protocol_menu.grid(
            row=row, column=1, padx=(0, 20), pady=8, sticky="w"
        )

        row = 4
        ctk.CTkLabel(self, text="DNS 服务器：", anchor="w").grid(
            row=row, column=0, padx=(20, 5), pady=8, sticky="w"
        )
        self.dns_entry = ctk.CTkEntry(
            self, placeholder_text="多个用空格分隔，留空使用默认"
        )
        self.dns_entry.insert(0, "223.5.5.5 223.6.6.6")
        self.dns_entry.grid(row=row, column=1, padx=(0, 20), pady=8, sticky="ew")

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=5, column=0, columnspan=2, pady=(10, 5))

        ctk.CTkLabel(frame, text="检查间隔（秒）：").pack(side="left", padx=(0, 5))
        self.interval_entry = ctk.CTkEntry(frame, width=60)
        self.interval_entry.insert(0, "10")
        self.interval_entry.pack(side="left", padx=5)

        ctk.CTkLabel(frame, text="稳定次数：").pack(side="left", padx=(15, 5))
        self.stability_entry = ctk.CTkEntry(frame, width=60)
        self.stability_entry.insert(0, "3")
        self.stability_entry.pack(side="left", padx=5)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=6, column=0, columnspan=2, pady=(15, 20))

        ctk.CTkButton(
            btn_frame, text="确定", width=100, command=self._on_ok
        ).pack(side="left", padx=10)
        ctk.CTkButton(
            btn_frame, text="取消", width=100, command=self._on_cancel
        ).pack(side="left", padx=10)

    def _load_data(self, data: dict):
        self.name_entry.delete(0, "end")
        self.name_entry.insert(0, data.get('name', ''))
        self.name_entry.configure(placeholder_text=data.get('name', ''))
        self.domain_entry.delete(0, "end")
        self.domain_entry.insert(0, data.get('domain', ''))
        self.port_entry.delete(0, "end")
        self.port_entry.insert(0, str(data.get('local_port', '')))
        self.protocol_var.set(data.get('protocol', 'tcp'))
        self.dns_entry.delete(0, "end")
        self.dns_entry.insert(0, data.get('dns_servers', ''))
        self.interval_entry.delete(0, "end")
        self.interval_entry.insert(0, str(data.get('interval', 10)))
        self.stability_entry.delete(0, "end")
        self.stability_entry.insert(0, str(data.get('stability', 3)))

    def _validate(self) -> Optional[dict]:
        name = self.name_entry.get().strip()
        domain = self.domain_entry.get().strip()
        port_str = self.port_entry.get().strip()
        protocol = self.protocol_var.get()
        dns_servers = self.dns_entry.get().strip()
        interval_str = self.interval_entry.get().strip()
        stability_str = self.stability_entry.get().strip()

        if not name:
            self._show_error("请输入名称")
            return None
        if " " in name:
            self._show_error("名称不能包含空格")
            return None
        if not domain:
            self._show_error("请输入域名")
            return None
        if not port_str or not port_str.isdigit():
            self._show_error("本地端口必须为数字")
            return None
        port = int(port_str)
        if port < 1 or port > 65535:
            self._show_error("端口范围 1-65535")
            return None

        interval = 10
        if interval_str:
            if not interval_str.isdigit():
                self._show_error("检查间隔必须为数字")
                return None
            interval = int(interval_str)

        stability = 3
        if stability_str:
            if not stability_str.isdigit():
                self._show_error("稳定次数必须为数字")
                return None
            stability = int(stability_str)

        return {
            'name': name,
            'domain': domain,
            'local_port': port,
            'protocol': protocol,
            'dns_servers': dns_servers,
            'interval': interval,
            'stability': stability,
        }

    def _show_error(self, msg: str):
        mb.showerror("输入错误", msg, parent=self)

    def _on_ok(self):
        result = self._validate()
        if result:
            self.result = result
            self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()
