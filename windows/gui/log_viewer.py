import customtkinter as ctk
from ..log_handler import RingBufferHandler


class LogViewer(ctk.CTkFrame):
    def __init__(self, parent, log_handler: RingBufferHandler, **kwargs):
        super().__init__(parent, **kwargs)
        self._handler = log_handler
        self._last_count = 0
        self._auto_scroll = True

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, pady=(0, 5), sticky="ew")
        top.grid_columnconfigure(0, weight=1)

        self.filter_var = ctk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._refresh())
        ctk.CTkEntry(
            top, textvariable=self.filter_var,
            placeholder_text="过滤日志..."
        ).grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.auto_scroll_btn = ctk.CTkButton(
            top, text="自动滚动 ✓", width=100,
            command=self._toggle_auto_scroll
        )
        self.auto_scroll_btn.grid(row=0, column=1, padx=5)

        ctk.CTkButton(
            top, text="清空", width=60,
            command=self._clear
        ).grid(row=0, column=2)

        self.text = ctk.CTkTextbox(self, font=("Consolas", 11), wrap="none")
        self.text.grid(row=1, column=0, sticky="nsew")

        self._schedule_poll()

    def _toggle_auto_scroll(self):
        self._auto_scroll = not self._auto_scroll
        self.auto_scroll_btn.configure(
            text=f"自动滚动 {'✓' if self._auto_scroll else '✗'}"
        )

    def _clear(self):
        self.text.delete("0.0", "end")
        self._last_count = 0

    def _schedule_poll(self):
        self._refresh()
        self.after(1000, self._schedule_poll)

    def _refresh(self):
        all_logs = self._handler.get_all()
        new_logs = all_logs[self._last_count:]
        filter_text = self.filter_var.get().strip().lower()

        if new_logs:
            for entry in new_logs:
                if filter_text and filter_text not in entry.lower():
                    continue
                self.text.insert("end", entry + "\n")

            if self._auto_scroll:
                self.text.see("end")

            self._last_count = len(all_logs)
