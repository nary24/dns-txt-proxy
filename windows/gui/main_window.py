import os
import socket
import tkinter.filedialog as tkfd
import tkinter.messagebox as tkmb
import customtkinter as ctk
from typing import Optional, Callable

from ..proxy_manager import ProxyManager
from ..log_handler import RingBufferHandler
from .. import settings
from .proxy_dialog import ProxyDialog
from .log_viewer import LogViewer

ROW_BG = ("white", "gray17")
SELECTED_BG = ("#D0E8FF", "#2B5B84")

COL_X = [8, 138, 348, 508, 562, 652, 858]
COL_W = [120, 200, 150, 50, 85, 200, 90]

ROW_H = 32
ROW_PAD = 22


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("223.5.5.5", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        pass
    return "127.0.0.1"


def _trunc(text, max_len):
    if len(text) > max_len:
        return text[:max_len - 2] + ".."
    return text


class MainWindow(ctk.CTk):
    def __init__(self, manager: ProxyManager, log_handler: RingBufferHandler,
                 on_config_change: Optional[Callable] = None):
        super().__init__()
        self._manager = manager
        self._log_handler = log_handler
        self._on_config_change = on_config_change
        self._selected_name: Optional[str] = None
        self._row_frames: dict[str, ctk.CTkFrame] = {}
        self._row_actions: dict[str, dict] = {}
        self._local_ip = get_local_ip()

        self.title("DNS TXT Proxy 管理器")
        self.geometry("1080x650")
        self.minsize(960, 500)

        self._build_ui()
        self._rebuild_rows()
        self._schedule_refresh()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        toolbar = ctk.CTkFrame(self)
        toolbar.grid(row=0, column=0, pady=(10, 0), padx=10, sticky="ew")

        self.add_btn = ctk.CTkButton(
            toolbar, text="＋ 添加", width=90, command=self._on_add)
        self.add_btn.pack(side="left", padx=5, pady=5)

        self.edit_btn = ctk.CTkButton(
            toolbar, text="✏ 编辑", width=90, command=self._on_edit)
        self.edit_btn.pack(side="left", padx=5, pady=5)

        ctk.CTkButton(toolbar, text="📁 配置文件", width=100,
                      command=self._on_settings).pack(side="right", padx=5, pady=5)

        self.refresh_btn = ctk.CTkButton(
            toolbar, text="⟳ 刷新", width=80, command=self._reload_from_config)
        self.refresh_btn.pack(side="right", padx=5, pady=5)

        header = ctk.CTkFrame(self, fg_color=("gray85", "gray25"), height=28)
        header.grid(row=1, column=0, pady=(5, 0), padx=10, sticky="ew")
        header.grid_propagate(False)

        hdrs = ["名称", "域名", "监听地址", "协议", "状态", "当前目标", "操作"]
        for i, t in enumerate(hdrs):
            lbl = ctk.CTkLabel(header, text=t, width=COL_W[i],
                               font=("Microsoft YaHei", 11, "bold"), anchor="w")
            lbl.place(x=COL_X[i], y=4)

        self.rows_frame = ctk.CTkScrollableFrame(self)
        self.rows_frame.grid(row=2, column=0, pady=(2, 5), padx=10, sticky="nsew")

        tabview = ctk.CTkTabview(self)
        tabview.grid(row=3, column=0, pady=(0, 5), padx=10, sticky="nsew")
        log_tab = tabview.add("日志")
        log_tab.grid_columnconfigure(0, weight=1)
        log_tab.grid_rowconfigure(0, weight=1)
        self.log_viewer = LogViewer(log_tab, self._log_handler)
        self.log_viewer.grid(row=0, column=0, sticky="nsew")

        self.status_bar = ctk.CTkLabel(
            self, text="", anchor="w", fg_color=("gray90", "gray20"))
        self.status_bar.grid(row=4, column=0, padx=10, pady=(0, 5), sticky="ew")

    def _build_row(self, frame, s):
        name = s['name']
        running = s['running']
        bg = SELECTED_BG if name == self._selected_name else ROW_BG
        frame.configure(fg_color=bg, height=ROW_H)
        frame.pack_propagate(False)
        frame.pack(fill="x", padx=2, pady=1)

        frame._bind_self = lambda e, n=name: self._select_row(n)
        frame.bind("<Button-1>", frame._bind_self)

        def _click(e, n=name): self._select_row(n)
        def _dblclick(e, n=name): self._select_row(n, edit=True)

        items = []

        name_lbl = ctk.CTkLabel(
            frame, text=_trunc(name, 18), anchor="w",
            font=("Microsoft YaHei", 12, "bold"), width=COL_W[0], height=ROW_PAD)
        name_lbl.place(x=COL_X[0], y=5)
        name_lbl.bind("<Button-1>", _click)
        name_lbl.bind("<Double-1>", _dblclick)

        domain_lbl = ctk.CTkLabel(
            frame, text=_trunc(s['domain'], 30), anchor="w",
            width=COL_W[1], height=ROW_PAD)
        domain_lbl.place(x=COL_X[1], y=5)
        domain_lbl.bind("<Button-1>", _click)
        domain_lbl.bind("<Double-1>", _dblclick)

        addr_lbl = ctk.CTkLabel(
            frame, text=f"{self._local_ip}:{s['local_port']}", anchor="w",
            width=COL_W[2], height=ROW_PAD)
        addr_lbl.place(x=COL_X[2], y=5)
        addr_lbl.bind("<Button-1>", _click)
        addr_lbl.bind("<Double-1>", _dblclick)

        proto_lbl = ctk.CTkLabel(
            frame, text=s['protocol'], anchor="center",
            width=COL_W[3], height=ROW_PAD)
        proto_lbl.place(x=COL_X[3], y=5)
        proto_lbl.bind("<Button-1>", _click)
        proto_lbl.bind("<Double-1>", _dblclick)

        status_text = "● 运行中" if running else "○ 已停止"
        status_color = "#2ECC71" if running else "#999999"
        status_lbl = ctk.CTkLabel(
            frame, text=status_text, text_color=status_color,
            anchor="center", width=COL_W[4], height=ROW_PAD)
        status_lbl.place(x=COL_X[4], y=5)
        status_lbl.bind("<Button-1>", _click)

        target_lbl = ctk.CTkLabel(
            frame, text=_trunc(s['target'], 30), anchor="w",
            width=COL_W[5], height=ROW_PAD)
        target_lbl.place(x=COL_X[5], y=5)
        target_lbl.bind("<Button-1>", _click)
        target_lbl.bind("<Double-1>", _dblclick)

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent",
                                 width=COL_W[6], height=ROW_PAD)
        btn_frame.place(x=COL_X[6], y=5)
        action_btn = ctk.CTkButton(
            btn_frame, width=36, height=ROW_PAD - 2,
            text="⏹" if running else "▶",
            fg_color="#1F538D" if running else "#2ECC71",
            command=lambda n=name: self._on_row_stop(n) if running
                                  else self._on_row_start(n))
        action_btn.place(x=0, y=0)
        del_btn = ctk.CTkButton(
            btn_frame, text="✕", width=36, height=ROW_PAD - 2,
            fg_color="#E74C3C", hover_color="#C0392B",
            command=lambda n=name: self._on_row_delete(n))
        del_btn.place(x=42, y=0)

        self._make_tooltip(name_lbl, name, 18)
        self._make_tooltip(domain_lbl, s['domain'], 30)
        self._make_tooltip(target_lbl, s['target'], 30)

        self._row_frames[name] = frame
        self._row_actions[name] = {
            'frame': frame, 'name': name, 'running': running,
            'status_lbl': status_lbl, 'action_btn': action_btn,
            'del_btn': del_btn,
            'target_lbl': target_lbl,
        }
        items.extend([name_lbl, domain_lbl, addr_lbl, proto_lbl,
                     status_lbl, target_lbl, action_btn, del_btn])

    def _make_tooltip(self, widget, full_text, trunc_len):
        if len(full_text) <= trunc_len:
            return
        tip = None
        def on_enter(e):
            nonlocal tip
            if tip is not None:
                return
            x = widget.winfo_rootx()
            y = widget.winfo_rooty() + widget.winfo_height() + 2
            tip = ctk.CTkToplevel(widget)
            tip.wm_overrideredirect(True)
            tip.wm_geometry(f"+{x}+{y}")
            lbl = ctk.CTkLabel(tip, text=full_text, fg_color="#FFFFCC",
                               text_color="black", corner_radius=4,
                               padx=6, pady=2)
            lbl.pack()
        def on_leave(e):
            nonlocal tip
            if tip is not None:
                tip.destroy()
                tip = None
        widget.bind("<Enter>", on_enter, add="+")
        widget.bind("<Leave>", on_leave, add="+")

    def _select_row(self, name: str, edit: bool = False):
        old = self._selected_name
        self._selected_name = name
        if old and old in self._row_frames:
            self._row_frames[old].configure(fg_color=ROW_BG)
        if name in self._row_frames:
            self._row_frames[name].configure(fg_color=SELECTED_BG)
        if edit:
            self._on_edit()

    def _on_row_start(self, name: str):
        self._manager.start_proxy(name)
        row = self._row_actions.get(name)
        if row:
            row['running'] = True
            self._update_row_ui(name)

    def _on_row_stop(self, name: str):
        self._manager.stop_proxy(name)
        row = self._row_actions.get(name)
        if row:
            row['running'] = False
            self._update_row_ui(name)

    def _on_row_delete(self, name: str):
        if tkmb.askyesno("确认删除", f"确定要删除端口映射「{name}」吗？",
                       parent=self):
            self._manager.remove_proxy(name)
            if self._selected_name == name:
                self._selected_name = None
            self._rebuild_rows()

    def _update_row_ui(self, name: str):
        row = self._row_actions.get(name)
        if not row:
            return
        running = row['running']
        row['action_btn'].configure(
            text="⏹" if running else "▶",
            fg_color="#1F538D" if running else "#2ECC71",
            command=lambda n=name: self._on_row_stop(n) if running
                                  else self._on_row_start(n))
        status_text = "● 运行中" if running else "○ 已停止"
        status_color = "#2ECC71" if running else "#999999"
        row['status_lbl'].configure(text=status_text, text_color=status_color)

    def _rebuild_rows(self):
        for f in list(self._row_frames.values()):
            f.destroy()
        self._row_frames.clear()
        self._row_actions.clear()

        for s in self._manager.get_status_list():
            frame = ctk.CTkFrame(self.rows_frame)
            self._build_row(frame, s)

        self._update_status_bar()

    def _update_status_bar(self):
        statuses = self._manager.get_status_list()
        running_count = sum(1 for s in statuses if s['running'])
        cfg = self._manager.get_config_path()
        self.status_bar.configure(
            text=f"总计 {len(statuses)} 个代理，{running_count} 个运行中  |  配置: {cfg}")

    def _on_add(self):
        dialog = ProxyDialog(self, title="添加端口映射")
        self.wait_window(dialog)
        if dialog.result:
            try:
                self._manager.add_proxy(dialog.result['name'], dialog.result)
                self._rebuild_rows()
            except ValueError as e:
                tkmb.showerror("错误", str(e), parent=self)

    def _on_edit(self):
        name = self._selected_name
        if not name:
            tkmb.showinfo("提示", "请先点击选择要编辑的代理", parent=self)
            return
        status_list = self._manager.get_status_list()
        proxy_info = next((s for s in status_list if s['name'] == name), None)
        if not proxy_info:
            return
        data = {'name': name, 'domain': proxy_info['domain'],
                'local_port': proxy_info['local_port'],
                'protocol': proxy_info['protocol'].lower()}
        config = self._manager._read_config()
        if config.has_section(name):
            data['dns_servers'] = config.get(name, 'dns_servers', fallback='')
            data['interval'] = config.getint(name, 'interval', fallback=10)
            data['stability'] = config.getint(name, 'stability', fallback=3)
        dialog = ProxyDialog(self, title="编辑端口映射", data=data)
        self.wait_window(dialog)
        if dialog.result:
            self._manager.update_proxy(name, dialog.result)
            self._rebuild_rows()

    def _on_settings(self):
        self.update_idletasks()
        current = self._manager.get_config_path()
        path = tkfd.askopenfilename(
            title="选择配置文件",
            filetypes=[("配置文件", "*.conf;*.ini"), ("所有文件", "*.*")],
            initialdir=os.path.dirname(current) if current else None,
            parent=self)
        if not path:
            return
        self.update_idletasks()
        if tkmb.askyesno("切换配置",
                         f"切换到「{path}」后将重新加载所有代理，确定吗？",
                         parent=self):
            settings.set_custom_config_path(path)
            self._manager.set_config_path(path)
            self._manager.reload_config()
            self._rebuild_rows()
            self.refresh_btn.configure(text="⟳ 刷新")
            if self._on_config_change:
                self._on_config_change(path)

    def _reload_from_config(self):
        self._manager.reload_config()
        self._rebuild_rows()
        self.refresh_btn.configure(text="⟳ 刷新")

    def _schedule_refresh(self):
        for s in self._manager.get_status_list():
            row = self._row_actions.get(s['name'])
            if not row:
                continue
            if row['running'] != s['running']:
                row['running'] = s['running']
                self._update_row_ui(s['name'])
            row['target_lbl'].configure(text=_trunc(s['target'], 30))
        self.after(3000, self._schedule_refresh)

    def iconify(self):
        self.withdraw()

    def _on_close(self):
        self.withdraw()
