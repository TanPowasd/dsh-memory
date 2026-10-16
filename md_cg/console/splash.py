# -*- coding: utf-8 -*-
"""启动小窗（stdlib tkinter）：双击 lingshu-console.bat 时先弹出无边框小窗，
后台找库、开库、起服务；就绪后小窗自动关闭，再由 server.main 打开浏览器。

样式与控制台亮色「纸本档案」同一套：暖纸底、墨色字、朱砂印章、宋体标题、
发丝线边框、墨蓝细进度线；右上角 × 可取消启动。

白箱边界（不静默降级）：
  · 小窗只是外壳，不碰记忆库：找库/开库/起服务全在 work(set_status) 里，由调用方给；
  · work 抛的异常原样带回主线程再抛，不吞；
  · 小窗不可用（tkinter 缺失 / 没有图形桌面 / 被 --no-splash 或
    MDCG_CONSOLE_SPLASH=0 关掉）时，直接在当前线程跑 work，并把原因交回调用方打印；
  · 本模块不读写任何文件。
"""
from __future__ import annotations

import queue
import sys
import threading
import time

__all__ = ["run_with_splash", "SPLASH_ENV", "SplashCancelled"]

#: 设为 0 / off / false / no 关闭启动小窗（与 --no-splash 同效）。
SPLASH_ENV = "MDCG_CONSOLE_SPLASH"

# 亮色纸本档案色板（与 index.html :root 同值）
_BG, _LINE, _TXT, _SUB, _FAINT = "#f4f1e8", "#dcd5c5", "#24211c", "#5b554a", "#8e8778"
_ACCENT, _SEAL, _GHOST = "#2b4c6f", "#a63d25", "#efeadf"
_SERIF = ("Noto Serif SC", "Source Han Serif SC", "Noto Serif CJK SC", "Songti SC",
          "SimSun", "宋体", "NSimSun")
_SANS = ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC",
         "Segoe UI")
_W, _H = 560, 330          # 96 DPI 下的逻辑尺寸，高 DPI 按比例放大
_MIN_SHOW = 0.7            # 秒：太快就绪时也至少显示这么久，免得一闪而过


class SplashCancelled(Exception):
    """用户点了小窗右上角 ×。"""


# 生效条件：可单独替换（守卫用它模拟「没装 tkinter」）；返回 tkinter 模块，失败抛 ImportError。
def _import_tk():
    import tkinter
    return tkinter


# 生效条件：enabled 为假 → "已关闭"；env[SPLASH_ENV] 为 0/off/false/no → "已关闭"；
# 其余返回 None（是否真能弹窗要到 Tk() 那步才知道，由 run_with_splash 判定）。
def _disabled_reason(enabled, env):
    if not enabled:
        return "已关闭"
    v = str((env or {}).get(SPLASH_ENV, "")).strip().lower()
    if v in ("0", "off", "false", "no"):
        return "已关闭"
    return None


# 生效条件：仅 Windows 上调用；把进程设为 DPI 感知，免得高分屏上小窗发糊。失败忽略（只影响清晰度）。
def _dpi_aware():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:                           # noqa: BLE001  老系统没有 shcore，只是会糊
        pass


def _pick(families, wanted):
    for name in wanted:
        if name in families:
            return name
    return "TkDefaultFont"


class _Splash:
    """无边框小窗。只在主线程里用；状态经 queue 由后台线程送进来。"""

    def __init__(self, tk, root):
        self.tk, self.root = tk, root
        from tkinter import font as tkfont
        fam = set(tkfont.families(root))
        serif, sans = _pick(fam, _SERIF), _pick(fam, _SANS)
        s = self.s = max(1.0, root.winfo_fpixels("1i") / 96.0)
        w, h = int(_W * s), int(_H * s)
        root.overrideredirect(True)
        root.configure(bg=_BG)
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry("%dx%d+%d+%d" % (w, h, (sw - w) // 2, (sh - h) // 2))
        try:
            root.attributes("-topmost", True)
        except Exception:                       # noqa: BLE001  个别窗口管理器不支持
            pass
        c = self.c = tk.Canvas(root, width=w, height=h, bg=_BG, highlightthickness=0, bd=0)
        c.pack(fill="both", expand=True)
        px = lambda v: int(v * s)               # noqa: E731
        # 底纹：右下角一个淡墨大字，被窗口边缘裁掉一角
        c.create_text(px(492), px(218), text="枢", fill=_GHOST, font=(serif, -px(240), "bold"))
        # 发丝线边框
        c.create_rectangle(0, 0, w - 1, h - 1, outline=_LINE)
        # 朱砂印章 + 标题
        cx, cy = px(166), px(148)
        c.create_rectangle(cx - px(34), cy - px(34), cx + px(34), cy + px(34),
                           fill=_SEAL, outline=_SEAL)
        c.create_rectangle(cx - px(29), cy - px(29), cx + px(29), cy + px(29),
                           outline="#f4e3dc", width=1)
        c.create_text(cx, cy + px(1), text="灵", fill="#fbf4ee", font=(serif, -px(38), "bold"))
        c.create_text(px(222), cy - px(12), text="灵枢 · 记忆", anchor="w", fill=_TXT,
                      font=(serif, -px(34), "bold"))
        sub = c.create_text(px(224), cy + px(24), text="本机记忆控制台", anchor="w", fill=_SUB,
                            font=(sans, -px(14)))
        # 「只读」小签（VS 的 INSIDERS 位置，换成朱砂描边），紧跟副标题
        bx, by = c.bbox(sub)[2] + px(10), cy + px(24)
        c.create_rectangle(bx, by - px(11), bx + px(44), by + px(11), outline=_SEAL)
        c.create_text(bx + px(22), by, text="只读", fill=_SEAL, font=(sans, -px(12), "bold"))
        # 底栏：状态 + 出处
        self.status = c.create_text(px(24), h - px(26), text="正在启动…", anchor="w",
                                    fill=_FAINT, font=(sans, -px(12)))
        c.create_text(w - px(24), h - px(26), text="dsh-memory", anchor="e", fill=_FAINT,
                      font=(serif, -px(13)))
        # 墨蓝细进度线（来回走）
        c.create_line(0, h - px(2), w, h - px(2), fill=_LINE, width=max(1, px(2)))
        self.bar = c.create_line(0, h - px(2), px(120), h - px(2), fill=_ACCENT,
                                 width=max(1, px(2)))
        self.bar_x, self.bar_d, self.w = 0, px(6), w
        # 右上角 ×
        self.cancelled = False
        x = c.create_text(w - px(20), px(18), text="×", fill=_FAINT, font=(sans, -px(18)))
        c.tag_bind(x, "<Enter>", lambda e: c.itemconfigure(x, fill=_TXT))
        c.tag_bind(x, "<Leave>", lambda e: c.itemconfigure(x, fill=_FAINT))
        c.tag_bind(x, "<Button-1>", lambda e: self._cancel())
        root.bind("<Escape>", lambda e: self._cancel())
        # 无边框窗可按住拖动
        c.bind("<ButtonPress-1>", self._grab)
        c.bind("<B1-Motion>", self._drag)

    def _cancel(self):
        self.cancelled = True
        self.set_status("正在取消…")

    def _grab(self, e):
        self._gx, self._gy = e.x, e.y

    def _drag(self, e):
        r = self.root
        r.geometry("+%d+%d" % (r.winfo_x() + e.x - self._gx, r.winfo_y() + e.y - self._gy))

    def set_status(self, text):
        self.c.itemconfigure(self.status, text=text)

    def tick(self):
        seg = int(120 * self.s)
        self.bar_x += self.bar_d
        if self.bar_x <= 0 or self.bar_x + seg >= self.w:
            self.bar_d = -self.bar_d
        h = int(_H * self.s)
        self.c.coords(self.bar, self.bar_x, h - int(2 * self.s), self.bar_x + seg,
                      h - int(2 * self.s))


# 生效条件：work 形如 work(set_status) -> result，set_status(str) 可在任何线程调用。
# 返回 (result, reason)：reason 为 None 表示小窗正常显示过；否则是没显示的原因（"已关闭" /
# "tkinter 不可用：…" / "没有图形桌面：…"），调用方据此打印，不静默。
# work 抛异常 → 原样在调用线程再抛；用户点 × → work 跑完后抛 SplashCancelled（work 的结果
# 先交给 on_cancel(result) 收尾，如关闭已起的服务）。
def run_with_splash(work, enabled=True, env=None, on_cancel=None):
    reason = _disabled_reason(enabled, env)
    if reason is None:
        try:
            tk = _import_tk()
        except ImportError as exc:
            reason = "tkinter 不可用：%s" % exc
    if reason is None:
        _dpi_aware()
        try:
            root = tk.Tk()
        except Exception as exc:                # noqa: BLE001  TclError：没有显示器/桌面
            reason = "没有图形桌面：%s" % exc
    if reason is not None:
        return work(lambda _t: None), reason

    try:
        ui = _Splash(tk, root)
    except Exception:
        root.destroy()
        raise
    q = queue.Queue()
    box = {}

    def runner():
        try:
            box["result"] = work(lambda t: q.put(("status", t)))
        except BaseException as exc:            # noqa: BLE001  带回主线程再抛
            box["error"] = exc
        q.put(("done", None))

    t0 = time.monotonic()
    threading.Thread(target=runner, name="console-startup", daemon=True).start()
    state = {"done": False}

    def poll():
        try:
            while True:
                kind, val = q.get_nowait()
                if kind == "status":
                    ui.set_status(val)
                else:
                    state["done"] = True
        except queue.Empty:
            pass
        if state["done"] and (ui.cancelled or "error" in box
                              or time.monotonic() - t0 >= _MIN_SHOW):
            root.quit()
            return
        ui.tick()
        root.after(30, poll)

    root.after(30, poll)
    try:
        root.mainloop()
    finally:
        try:
            root.destroy()
        except Exception:                       # noqa: BLE001  窗口已被系统关掉
            pass
    if "error" in box:
        raise box["error"]
    if ui.cancelled:
        if on_cancel is not None:
            on_cancel(box.get("result"))
        raise SplashCancelled()
    return box.get("result"), None
