# -*- coding: utf-8 -*-
"""test_console.py · 记忆控制台（md_cg/console）守卫

守卫断言（每条都能被对应的定点变异打红，见 --mutate）：
  G1 只读：调用全部数据面函数 + 全部 HTTP 路由后，库根下每个文件逐字节不变
     （含 _access.log —— search 若 record=True 即变红）。
  G2 身份恒只读：make_principal 无令牌 / 显式密级两路 can_write 均为 False，
     且经该身份打开的库 add() 抛 AccessDenied。
  G3 本机闸：host_allowed 只认 127.0.0.1/localhost/[::1]；HTTP 层外来 Host → 421、
     外来 Origin → 403、POST → 405、本机 GET → 200。
  G4 不凭空建库：open_cg 对不存在目录返回 root_missing 且目录仍不存在。
  G5 可见性同口径：--clearance internal 时 secret 节点不出现在 overview/browse/search，
     node() 对它与「不存在」同形（node_not_found）。
  G6 前端渲染纪律：index.html 不含 innerHTML/outerHTML/insertAdjacentHTML/document.write。
  G7 静态禁写：api.py / server.py 源码不调用任何写接口名。
  G8 自动找库：MDCG_ROOT 指向非记忆库时回落 ~/.lingshu/memory；都不是则返回 None
     并列出全部已找位置；显式 --root 原样采用不猜。

跑法（仓库根）：
  python -X utf8 -m md_cg.test_console            # 守卫
  python -X utf8 -m md_cg.test_console --mutate   # 定点变异自证：每条变异须点红
"""
from __future__ import annotations

import hashlib
import http.client
import os
import re
import shutil
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from md_cg.console import api, server          # noqa: E402
from md_cg.mdcos import MdCGSecure             # noqa: E402
from md_cg.security import AccessDenied, Principal   # noqa: E402

PASS = 0
FAIL = 0
_HERE = os.path.dirname(os.path.abspath(__file__))


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [ok] %s" % name)
    else:
        FAIL += 1
        print("  [✘] %s  %s" % (name, detail))


# 生效条件：在 root 下用设计者身份写 4 个节点（其中 sec_note 为 secret、来自另一会话）+ 2 条近期事件 + 1 条提案，返回 root。
def _seed(root):
    p = Principal(actor="seed", clearance="secret", can_write=True, can_admin=True,
                  role="designer", auth_mode="local-cli", session="seed-sess")
    cg = MdCGSecure(root, principal=p, autoflush=1)
    cg.add("pref_editor", "用户偏好用 VS Code 写 Python。", layer="knowledge", tags=["偏好"])
    cg.add("habit_run", "每周二早上跑步 5 公里。", layer="contextual", tags=["习惯"])
    cg.add("xss_probe", "<img src=x onerror=alert(1)> 转义测试", layer="knowledge")
    cg.add("sec_note", "机密：保险箱密码提示是生日。", layer="knowledge",
           sensitivity="secret")
    cg.remember_event("user", "今天测试控制台")
    cg.remember_event("assistant", "好的")
    cg.propose("prop_hike", "用户周末喜欢爬山。", layer="contextual", tags=["爱好"])
    cg.close()
    return root


# 生效条件：遍历 root 下全部文件，返回 {相对路径: sha256}。
def _snapshot(root):
    out = {}
    for d, _dirs, files in os.walk(root):
        for f in files:
            fp = os.path.join(d, f)
            with open(fp, "rb") as fh:
                out[os.path.relpath(fp, root)] = hashlib.sha256(fh.read()).hexdigest()
    return out


# 生效条件：对 127.0.0.1:port 发一次请求，返回 (status, body_bytes)；headers 覆盖缺省 Host。
def _req(port, path, method="GET", headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": "127.0.0.1:%d" % port}
    h.update(headers or {})
    c.request(method, path, headers=h)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body


def run_guards():
    global PASS, FAIL
    PASS = FAIL = 0
    tmp = tempfile.mkdtemp(prefix="console_guard_")
    try:
        root = _seed(os.path.join(tmp, "mem"))

        # ---- G1 只读 ----
        print("== G1 只读：全部数据面 + 路由调用后盘面逐字节不变 ==")
        cg, err = api.open_cg(root)
        check("G1.0 open_cg 成功", cg is not None and err is None, str(err))
        before = _snapshot(root)
        ov = api.overview(cg)
        api.search(cg, "跑步")
        api.search(cg, "VS Code", layer="knowledge", k=5)
        api.browse(cg)
        api.browse(cg, layer="contextual", offset=0, limit=1)
        api.node(cg, "pref_editor")
        api.node(cg, "no_such_node")
        api.timeline(cg)
        rv = api.review(cg)
        srv = server.make_server(cg, port=0)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        port = srv.server_address[1]
        codes = {}
        for path in ("/", "/api/overview", "/api/search?q=%E8%B7%91%E6%AD%A5",
                     "/api/browse", "/api/node?id=habit_run", "/api/timeline",
                     "/api/review"):
            codes[path] = _req(port, path)[0]
        after = _snapshot(root)
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        check("G1.1 盘面逐字节不变", not changed, "变化文件：%s" % changed)
        check("G1.2 全部路由 200", all(v == 200 for v in codes.values()), str(codes))
        check("G1.3 概览计数（可见 4 条：设计者口径含 secret）", ov.get("total") == 4, str(ov.get("total")))
        check("G1.4 待复核可读 1 条", rv.get("ok") and rv.get("total") == 1, str(rv))

        # ---- G3 本机闸 ----
        print("== G3 本机闸 ==")
        check("G3.1 host_allowed 本机三形态",
              all(server.host_allowed(h) for h in
                  ("127.0.0.1", "127.0.0.1:8765", "localhost:1", "[::1]:8765")))
        check("G3.2 host_allowed 拒外来/空",
              not any(server.host_allowed(h) for h in
                      ("evil.com", "127.0.0.1.evil.com", "evil.com:8765", "", None)))
        check("G3.3 外来 Host → 421",
              _req(port, "/api/overview", headers={"Host": "evil.com"})[0] == 421)
        check("G3.4 外来 Origin → 403",
              _req(port, "/api/overview", headers={"Origin": "http://evil.com"})[0] == 403)
        check("G3.5 POST → 405", _req(port, "/api/overview", method="POST")[0] == 405)
        check("G3.6 本机 Origin GET → 200",
              _req(port, "/api/overview",
                   headers={"Origin": "http://127.0.0.1:%d" % port})[0] == 200)
        srv.shutdown()
        srv.server_close()

        # ---- G2 身份恒只读 ----
        print("== G2 身份恒只读 ==")
        p1 = api.make_principal(env={})
        p2 = api.make_principal("internal", env={})
        check("G2.1 两路 can_write=False",
              p1.can_write is False and p2.can_write is False)
        try:
            cg.add("should_fail", "x")
            denied = False
        except AccessDenied:
            denied = True
        check("G2.2 控制台身份 add() → AccessDenied", denied)
        cg.close()

        # ---- G5 可见性 ----
        print("== G5 可见性同口径（clearance=internal） ==")
        cgi, _ = api.open_cg(root, clearance="internal")
        ids_b = {c["id"] for c in api.browse(cgi)["items"]}
        ids_s = {c["id"] for c in api.search(cgi, "保险箱 密码")["items"]}
        check("G5.1 overview 不计 secret", api.overview(cgi)["total"] == 3)
        check("G5.2 browse 不列 secret", "sec_note" not in ids_b, str(ids_b))
        check("G5.3 search 不出 secret", "sec_note" not in ids_s, str(ids_s))
        n_hidden = api.node(cgi, "sec_note")
        n_none = api.node(cgi, "no_such_node")
        check("G5.4 node 对不可见与不存在同形",
              n_hidden.get("error") == n_none.get("error") == "node_not_found"
              and set(n_hidden) == set(n_none))
        cgi.close()

        # ---- G4 不凭空建库 ----
        print("== G4 不凭空建库 ==")
        ghost = os.path.join(tmp, "ghost_root")
        cgx, errx = api.open_cg(ghost)
        check("G4.1 root_missing", cgx is None and (errx or {}).get("error") == "root_missing")
        check("G4.2 目录未被创建", not os.path.exists(ghost))
        plain = os.path.join(tmp, "plain_dir")
        os.makedirs(plain)
        cgy, erry = api.open_cg(plain)
        check("G4.3 非记忆库目录 → not_a_memory_root",
              cgy is None and (erry or {}).get("error") == "not_a_memory_root")
        check("G4.4 非记忆库目录未被写入", os.listdir(plain) == [])

        # ---- G8 自动找库 ----
        print("== G8 自动找库 ==")
        home = os.path.join(tmp, "home")
        saved = {k: os.environ.get(k) for k in ("MDCG_ROOT", "MDCG_DATA_ROOT")}
        os.environ["MDCG_ROOT"] = plain               # 配置指向一个非记忆库目录
        os.environ.pop("MDCG_DATA_ROOT", None)
        try:
            r0, tried0 = api.resolve_root(home=home)
            check("G8.1 都不是记忆库 → None 且列出两处",
                  r0 is None and len(tried0) == 2 and tried0[1].endswith(
                      os.path.join(".lingshu", "memory")), str((r0, tried0)))
            check("G8.2 探测不建目录", not os.path.exists(home))
            _seed(os.path.join(home, ".lingshu", "memory"))
            r1, _ = api.resolve_root(home=home)
            check("G8.3 回落 ~/.lingshu/memory",
                  r1 == os.path.join(home, ".lingshu", "memory"), str(r1))
            os.environ["MDCG_ROOT"] = root
            r2, _ = api.resolve_root(home=home)
            check("G8.4 MDCG_ROOT 是记忆库时优先", os.path.abspath(r2) == os.path.abspath(root), str(r2))
            check("G8.5 显式 --root 原样采用", api.resolve_root("X:/given", home=home)[0] == "X:/given")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- G6 / G7 静态 ----
    print("== G6 前端渲染纪律 / G7 静态禁写 ==")
    with open(os.path.join(_HERE, "console", "index.html"), encoding="utf-8") as f:
        html = f.read()
    bad = [w for w in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write")
           if w in html]
    check("G6.1 index.html 无 HTML 注入面", not bad, str(bad))
    write_names = (r"\.add\(", r"\.propose\(", r"\.forget", r"review_decide", r"\.set_state\(",
                   r"\.set_verification\(", r"\.update_tags\(", r"\.remember_event\(",
                   r"\.flush\(", r"record=True", r"\.append_edge\(", r"clear_recent")
    for mod in ("api.py", "server.py"):
        with open(os.path.join(_HERE, "console", mod), encoding="utf-8") as f:
            src = f.read()
        hits = [w for w in write_names if re.search(w, src)]
        check("G7 %s 无写接口调用" % mod, not hits, str(hits))
    print("\n结果：%d 通过 / %d 失败" % (PASS, FAIL))
    return FAIL


# ---- 定点变异：每条都须让守卫点红 ----
def _mutations():
    orig_search = api.search
    orig_mp = api.make_principal
    orig_host = server.host_allowed
    orig_open = api.open_cg
    orig_resolve = api.resolve_root

    def m6_no_probe(explicit=None, home=None):          # G8：不判是否记忆库，直接取第一候选
        r, tried = orig_resolve(explicit, home)
        if explicit:
            return r, tried
        from md_cg import datapath
        return datapath.mdcg_root(), tried

    def m1_search_records(cg, q, layer=None, k=20):     # G1：写访问日志
        cg.search(q, layer=layer, k=5, record=True)
        return orig_search(cg, q, layer, k)

    def m2_writable(clearance=None, env=None):          # G2：身份可写
        p = orig_mp(clearance, env)
        p.can_write = True
        return p

    def m4_mkdir(root, clearance=None, env=None):       # G4：凭空建库
        if root:
            os.makedirs(root, exist_ok=True)
        return orig_open(root, clearance, env)

    def m5_clearance_ignored(clearance=None, env=None):  # G5：密级参数被忽略
        return orig_mp(None, env)

    return [
        ("M1 search record=True", api, "search", m1_search_records),
        ("M2 身份 can_write=True", api, "make_principal", m2_writable),
        ("M3 host_allowed 恒真", server, "host_allowed", lambda h: True),
        ("M4 open_cg 建目录", api, "open_cg", m4_mkdir),
        ("M5 忽略 --clearance", api, "make_principal", m5_clearance_ignored),
        ("M6 找库不判记忆库", api, "resolve_root", m6_no_probe),
    ]


def run_mutations():
    escaped = []
    for name, mod, attr, fn in _mutations():
        orig = getattr(mod, attr)
        setattr(mod, attr, fn)
        try:
            print("\n######## 变异 %s ########" % name)
            fails = run_guards()
        except Exception as exc:                        # noqa: BLE001  抛异常也算红
            print("  变异下守卫抛 %s: %s（记为红）" % (type(exc).__name__, exc))
            fails = 1
        finally:
            setattr(mod, attr, orig)
        print(">> %s：%s" % (name, "点红 ✔" if fails else "未点红 ✘"))
        if not fails:
            escaped.append(name)
    print("\n变异自证：%d 条，逃逸 %d 条 %s" % (len(_mutations()), len(escaped), escaped))
    return 1 if escaped else 0


if __name__ == "__main__":
    if "--mutate" in sys.argv:
        sys.exit(run_mutations())
    sys.exit(1 if run_guards() else 0)
