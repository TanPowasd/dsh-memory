# -*- coding: utf-8 -*-
"""记忆控制台 HTTP 层（stdlib only）：只听 127.0.0.1，只有 GET。

路由（全部只读）：
  GET /                 → 单页界面 index.html
  GET /api/overview     → api.overview
  GET /api/search?q=&layer=&k=
  GET /api/browse?layer=&offset=&limit=
  GET /api/node?id=
  GET /api/timeline?limit=
  GET /api/review
其它方法一律 405；未知路径 404。

本机防护（白箱条件）：
  · Host 头须为 127.0.0.1 / localhost（可带端口）——否则 421（防 DNS rebinding：
    恶意网页把自己的域名解析到 127.0.0.1 后读你的记忆）；
  · 带 Origin 的请求，Origin 须同为本机——否则 403；
  · 响应带 nosniff / no-referrer / CSP（default-src 'self'），正文一律由前端
    textContent 渲染，不走 innerHTML。
"""
from __future__ import annotations

import json
import os
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import api

__all__ = ["make_server", "main", "DEFAULT_PORT", "host_allowed"]

#: 缺省端口（被占用时自动换一个空闲端口，并在窗口里打印实际地址）。
DEFAULT_PORT = 8765
_HERE = os.path.dirname(os.path.abspath(__file__))
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "[::1]")


# 生效条件：host 为 None/空串 → False；去掉末尾 ":端口" 后小写，命中 _LOCAL_HOSTS 之一 → True，其余 False。
def host_allowed(host):
    if not host:
        return False
    h = str(host).strip().lower()
    if h.startswith("["):                      # [::1]:8765
        h = h.split("]")[0] + "]"
    elif ":" in h:
        h = h.rsplit(":", 1)[0]
    return h in _LOCAL_HOSTS


# 生效条件：origin 为空（同源导航/curl 不带）→ True；否则取其 netloc 交 host_allowed 判定。
def origin_allowed(origin):
    if not origin:
        return True
    return host_allowed(urlsplit(origin).netloc)


# 生效条件：读 _HERE/index.html（UTF-8）返回 bytes；文件缺失抛 OSError 由调用方转 500。
def _index_html():
    with open(os.path.join(_HERE, "index.html"), "rb") as f:
        return f.read()


# 生效条件：由 make_server 绑定 cg 后实例化；do_GET 先过 Host/Origin 闸，再按路径分派到 api 纯读函数，结果 JSON 化（ensure_ascii=False, default=str）；api 抛未预期异常 → 500 且 body 带 {"ok":false,"error":"internal","detail":类型: 消息}（不吞）；其余 HTTP 方法 405。
class _Handler(BaseHTTPRequestHandler):
    cg = None
    lock = None
    server_version = "LingshuConsole/1"

    def log_message(self, fmt, *args):         # 静音逐请求日志（窗口里只留启动信息）
        return

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str)
                   .encode("utf-8"), "application/json; charset=utf-8")

    def _deny_method(self):
        self._json(405, {"ok": False, "error": "method_not_allowed",
                         "hint": "控制台只读，只接受 GET。"})

    do_POST = do_PUT = do_DELETE = do_PATCH = _deny_method

    def do_GET(self):                           # noqa: N802
        if not host_allowed(self.headers.get("Host")):
            return self._json(421, {"ok": False, "error": "host_not_local"})
        if not origin_allowed(self.headers.get("Origin")):
            return self._json(403, {"ok": False, "error": "origin_not_local"})
        u = urlsplit(self.path)
        qs = {k: v[-1] for k, v in parse_qs(u.query).items()}
        if u.path in ("/", "/index.html"):
            try:
                return self._send(200, _index_html(), "text/html; charset=utf-8")
            except OSError as exc:
                return self._json(500, {"ok": False, "error": "ui_missing",
                                        "detail": str(exc)})
        routes = {
            "/api/overview": lambda: api.overview(self.cg),
            "/api/search": lambda: api.search(self.cg, qs.get("q"),
                                              qs.get("layer"), qs.get("k", 20)),
            "/api/browse": lambda: api.browse(self.cg, qs.get("layer"),
                                              qs.get("offset", 0), qs.get("limit", 50)),
            "/api/node": lambda: api.node(self.cg, qs.get("id")),
            "/api/timeline": lambda: api.timeline(self.cg, qs.get("limit", 100)),
            "/api/review": lambda: api.review(self.cg),
        }
        fn = routes.get(u.path)
        if fn is None:
            return self._json(404, {"ok": False, "error": "not_found"})
        try:
            with self.lock:                     # MdCG 非线程安全：串行化读
                out = fn()
        except Exception as exc:                # noqa: BLE001
            return self._json(500, {"ok": False, "error": "internal",
                                    "detail": "%s: %s" % (type(exc).__name__, exc)})
        self._json(200, out)


# 生效条件：cg 为已打开的 MdCG 族实例；port 为 0 → 由系统分配；port 被占用（OSError）且 fallback 为真 → 改用 0 重试一次；返回绑定在 127.0.0.1 的 ThreadingHTTPServer（daemon 线程）。
def make_server(cg, port=DEFAULT_PORT, fallback=True):
    handler = type("Handler", (_Handler,), {"cg": cg, "lock": threading.Lock()})
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", int(port)), handler)
    except OSError:
        if not fallback or int(port) == 0:
            raise
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    return srv


# 生效条件：Windows 控制台缺省代码页（CP936 等）下把 stdout/stderr reconfigure 成 UTF-8 + errors="replace" + 行缓冲（输出重定向时启动地址也立即可见）（与 mcp_server._force_utf8_stdio 同款纵深）；无 reconfigure 的流跳过。
def _utf8_stdio():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except (AttributeError, ValueError):
            pass


# 生效条件：argv 解析 --root（缺省经 api.resolve_root 依次探测 datapath.mdcg_root() 与 ~/.lingshu/memory，都不是记忆库则列出已找位置并返回 2）/ --port（缺省 DEFAULT_PORT）/ --clearance / --no-browser；open_cg 失败 → 打印中文原因与下一步并返回 2；令牌校验失败 → 返回 3；成功则打印实际地址、按需打开浏览器并 serve_forever，Ctrl+C 退出返回 0。
def main(argv=None):
    import argparse
    _utf8_stdio()
    ap = argparse.ArgumentParser(prog="python -m md_cg.console",
                                 description="灵枢记忆控制台（本机只读网页）")
    ap.add_argument("--root", help="记忆库目录（缺省：MDCG_ROOT / paths.json / 默认数据根）")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--clearance", default=None,
                    help="可读密级上限（缺省 %s；有 MDCG_TOKEN 时以令牌为准）"
                         % api.DEFAULT_CLEARANCE)
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    a = ap.parse_args(argv)
    root, tried = api.resolve_root(a.root)
    if not root:
        print("[灵枢控制台] 没有找到记忆库。已经找过：")
        for t in tried:
            print("    " + t)
        print("[灵枢控制台] 请先让接入灵枢的 Agent 记住一件事，或用 --root 指定记忆库目录"
              "（就是 MCP 配置里的 MDCG_ROOT）。")
        return 2
    try:
        cg, err = api.open_cg(root, a.clearance)
    except Exception as exc:                    # noqa: BLE001  令牌/密级错误
        print("[灵枢控制台] 身份校验失败：%s: %s" % (type(exc).__name__, exc))
        return 3
    if err:
        print("[灵枢控制台] 打不开记忆库：" + err.get("hint", err.get("error", "")))
        return 2
    srv = make_server(cg, a.port)
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    if srv.server_address[1] != a.port:
        print("[灵枢控制台] 端口 %d 被占用，已改用 %d" % (a.port, srv.server_address[1]))
    print("[灵枢控制台] 记忆库：%s" % cg.root)
    print("[灵枢控制台] 已启动（只读）：%s" % url)
    print("[灵枢控制台] 关闭这个窗口或按 Ctrl+C 即可退出。")
    if not a.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        try:
            cg.close()
        except Exception:                       # noqa: BLE001
            pass
    return 0
