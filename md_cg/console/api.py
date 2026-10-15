# -*- coding: utf-8 -*-
"""记忆控制台数据面：纯读函数（cg → dict），与 HTTP 层解耦，便于守卫直测。

纪律：
  · 每个函数只调用读接口（index 读、get、search(record=False)、recent_events、
    review_list、auditview.build）；任何写接口都不在本模块出现
    （守卫 test_console.py「静态禁写」逐个点名检查）。
  · 失败不静默：返回 {"ok": False, "error": <机器码>, "hint": <中文下一步>}。
  · 可见性只走 ``auditview._readable_guard``（= MdCGSecure._readable），不另写口径。
"""
from __future__ import annotations

import os
import time

__all__ = ["open_cg", "make_principal", "resolve_root", "is_memory_root", "overview", "search", "browse",
           "node", "timeline", "review", "related", "inspect", "SNIPPET_MAX", "PAGE_MAX",
           "RELATED_TIERS", "SIM_CLEARANCES"]

#: 列表/搜索摘要截断字数（只影响显示，正文全文在节点详情里）。
SNIPPET_MAX = 160
#: 单页上限（防一次把大库全读进浏览器）。
PAGE_MAX = 200
#: 本机控制台缺省可读密级（needs-owner-decision：见 PR 说明「身份口径」）。
DEFAULT_CLEARANCE = "secret"


# 生效条件：env 缺省取 os.environ；MDCG_TOKEN 非空 → tokens.verify_token 校验（失败抛 TokenError，调用方拒启），成功后把 can_write/can_admin 之外的身份原样保留、can_write 强制 False；无令牌 → 构造本机只读身份 Principal(actor="console-ui", clearance=clearance 或 DEFAULT_CLEARANCE, can_write=False, can_admin=True, role="designer", auth_mode="local-ui", session="console")；两种路径返回的身份 can_write 恒为 False。
def make_principal(clearance=None, env=None):
    """控制台身份：恒只读。

    can_admin=True 的理由（存疑→需设计者裁）：MdCGSecure._readable 对 private/secret
    采用「会话绑定」，非 admin 只能看到本会话写的节点——本机主人打开自己的库却看不到
    其它会话的私密记忆，控制台即失去意义。本模块不暴露任何 admin 操作，admin 位只用于
    读可见性豁免；写权限由 can_write=False 在库层封死。
    """
    from ..security import Principal
    env = os.environ if env is None else env
    token = (env.get("MDCG_TOKEN") or "").strip()
    if token:
        from ..tokens import verify_token
        p = verify_token(token, tenant=env.get("MDCG_TENANT"))
        p.can_write = False
        return p
    return Principal(actor="console-ui",
                     clearance=clearance or DEFAULT_CLEARANCE,
                     can_write=False, can_admin=True, role="designer",
                     auth_mode="local-ui", session="console")


# 生效条件：root 为已存在目录，且其下存在 _index.json 或 mdcg.LAYERS 任一层目录 → True；其余（含不存在、非目录）False；只 stat 不写。
def is_memory_root(root):
    if not root or not os.path.isdir(root):
        return False
    from ..mdcg import LAYERS
    marks = [os.path.join(root, "_index.json")] + [os.path.join(root, L) for L in LAYERS]
    return any(os.path.exists(m) for m in marks)


# 生效条件：explicit 非空 → 原样返回 (explicit, [explicit])（显式指定不猜）；否则按序探测候选——① datapath.mdcg_root()（含 MDCG_ROOT / paths.json / 默认数据根）② home/.lingshu/memory（lingshu init 的缺省根，home 缺省 os.path.expanduser("~")）——返回第一个 is_memory_root 为真的 (root, tried)；都不是记忆库时返回 (None, tried) 由调用方如实列出已找过的位置；datapath 抛 ValueError（Windows 保留设备名）时该候选记为 "<无效: 消息>" 并继续。
def resolve_root(explicit=None, home=None):
    if explicit:
        return explicit, [explicit]
    tried = []
    try:
        from .. import datapath
        tried.append(datapath.mdcg_root())
    except ValueError as exc:
        tried.append("<无效: %s>" % exc)
    tried.append(os.path.join(home or os.path.expanduser("~"), ".lingshu", "memory"))
    for cand in tried:
        if not cand.startswith("<") and is_memory_root(cand):
            return cand, tried
    return None, tried


# 生效条件：root 为空串/None → 返回 (None, {"ok":False,"error":"no_root"})；root 不是已存在目录 → (None, {"error":"root_missing"})（**不创建目录**：控制台不得因打开而凭空建库）；目录存在但无 _index.json 且无任何层目录 → (None, {"error":"not_a_memory_root"})；其余以 make_principal(clearance) 构造 MdCGSecure(root, autoflush=1) 返回 (cg, None)。
def open_cg(root, clearance=None, env=None):
    if not root:
        return None, {"ok": False, "error": "no_root",
                      "hint": "没有找到记忆库位置。请设置环境变量 MDCG_ROOT，"
                              "或运行 lingshu init 后再打开控制台。"}
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return None, {"ok": False, "error": "root_missing", "root": root,
                      "hint": "记忆库目录不存在：%s。控制台只读，不会替你新建；"
                              "请先让 Agent 写入一条记忆，或检查 MDCG_ROOT。" % root}
    if not is_memory_root(root):
        return None, {"ok": False, "error": "not_a_memory_root", "root": root,
                      "hint": "这个目录看起来不是灵枢记忆库（没有 _index.json 也没有层目录）："
                              "%s" % root}
    from ..mdcos import MdCGSecure
    cg = MdCGSecure(root, principal=make_principal(clearance, env), autoflush=1)
    return cg, None


# 生效条件：cg 为 MdCG 族实例；返回 [(node_id, entry)]——取 cg.index["nodes"] 全部条目，经 auditview._readable_guard(cg) 判可见，判定抛异常按不可见（fail-closed），不读盘。
def _visible_entries(cg):
    from ..auditview import _readable_guard
    ok = _readable_guard(cg)
    out = []
    for nid, e in list((cg.index or {}).get("nodes", {}).items()):
        try:
            if ok(e):
                out.append((nid, e))
        except Exception:                                    # noqa: BLE001
            continue                                         # 判定异常 = 不可见
    return out


# 生效条件：text 非 str 时按空串；把连续空白折叠成单空格后，长度超 n（缺省 SNIPPET_MAX）截断并补「…」。
def _snip(text, n=SNIPPET_MAX):
    s = " ".join(str(text or "").split()) if isinstance(text, str) else ""
    return s if len(s) <= n else s[:n] + "…"


# 生效条件：rec 为 cg.get 返回的 dict（或 None）；返回卡片字典 {id, layer, tags, created_at, lifecycle_state, verification_state, sensitivity, snippet}；rec 为 None 时 snippet 为空且 unreadable=True（如实标出读不到，不编造）。
def _card(nid, entry, rec):
    fm = (rec or {}).get("frontmatter") or {}
    e = entry or {}
    return {
        "id": nid,
        "layer": fm.get("layer") or e.get("layer"),
        "tags": list(fm.get("tags") or e.get("tags") or []),
        "created_at": fm.get("created_at") or e.get("created_at"),
        "lifecycle_state": fm.get("lifecycle_state") or e.get("lifecycle_state"),
        "verification_state": fm.get("verification_state") or e.get("verification_state"),
        "sensitivity": e.get("sensitivity") or fm.get("sensitivity"),
        "importance": fm.get("importance", e.get("importance")),
        "snippet": _snip((rec or {}).get("content")),
        "unreadable": rec is None,
    }


# 生效条件：now 缺省取 time.time()；统计可见条目的总数、按 layer / lifecycle_state / verification_state 计数、created_at 落在近 7 天内的数量；待复核数取 review(cg)["total"]（失败记 None 并带 review_error）；近期事件数取 recent_events(limit=0) 长度；返回 ok=True 的概览字典，含 root 与身份摘要（actor/clearance/can_write）。
def overview(cg, now=None):
    now = time.time() if now is None else now
    ents = _visible_entries(cg)
    by_layer, by_life, by_ver = {}, {}, {}
    week = 0
    for _nid, e in ents:
        for d, k in ((by_layer, e.get("layer")), (by_life, e.get("lifecycle_state")),
                     (by_ver, e.get("verification_state"))):
            k = k or "未标注"
            d[k] = d.get(k, 0) + 1
        try:
            if now - float(e.get("created_at") or 0) <= 7 * 86400:
                week += 1
        except (TypeError, ValueError):
            pass
    rv = review(cg)
    try:
        recent_n = len(cg.recent_events(limit=0))
    except Exception as exc:                                 # noqa: BLE001
        recent_n = None
        recent_err = "%s: %s" % (type(exc).__name__, exc)
    else:
        recent_err = None
    p = getattr(cg, "principal", None)
    return {
        "ok": True, "root": cg.root, "total": len(ents),
        "by_layer": by_layer, "by_lifecycle": by_life, "by_verification": by_ver,
        "new_7d": week,
        "review_pending": rv.get("total") if rv.get("ok") else None,
        "review_error": None if rv.get("ok") else rv.get("error"),
        "recent_events": recent_n, "recent_error": recent_err,
        "principal": {"actor": getattr(p, "actor", None),
                      "clearance": getattr(p, "clearance", None),
                      "can_write": bool(getattr(p, "can_write", False)),
                      "auth_mode": getattr(p, "auth_mode", None)},
    }


# 生效条件：q 去空白为空 → {"ok":False,"error":"empty_query"}；k 非数回落 20 并钳 [1, PAGE_MAX]；layer 空串按 None；调用 cg.search(q, layer, k, record=False)（record=False：不写访问日志）；ValueError → {"ok":False,"error":"bad_query"}；结果逐条附 score 与资格四态 {state, reason}，并带 meta.tier/scanned。
def search(cg, q, layer=None, k=20):
    q = str(q or "").strip()
    if not q:
        return {"ok": False, "error": "empty_query", "hint": "请输入要找的内容。"}
    try:
        k = max(1, min(PAGE_MAX, int(k)))
    except (TypeError, ValueError):
        k = 20
    try:
        res, meta = cg.search(q, layer=layer or None, k=k, record=False)
    except ValueError as exc:
        return {"ok": False, "error": "bad_query", "hint": str(exc)}
    items = []
    for nd, score, qual in res or []:
        nid = nd.get("id")
        c = _card(nid, (cg.index or {}).get("nodes", {}).get(nid), nd)
        c["score"] = round(float(score or 0), 4)
        c["qualification"] = {"state": (qual or {}).get("state"),
                              "reason": (qual or {}).get("reason")}
        items.append(c)
    return {"ok": True, "query": q, "items": items, "total": len(items),
            "meta": {"tier": (meta or {}).get("tier"),
                     "scanned": (meta or {}).get("scanned")}}


# 生效条件：layer 非空时只留该层；按 created_at 降序（缺值按 0 排最后）；offset/limit 非数分别回落 0/50，limit 钳 [1, PAGE_MAX]；只对当页条目 cg.get 读正文（大库不全读）；返回 {ok, total, offset, limit, items}。
def browse(cg, layer=None, offset=0, limit=50):
    try:
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        offset = 0
    try:
        limit = max(1, min(PAGE_MAX, int(limit)))
    except (TypeError, ValueError):
        limit = 50
    ents = _visible_entries(cg)
    if layer:
        ents = [(n, e) for n, e in ents if e.get("layer") == layer]

    def _t(pair):
        try:
            return float(pair[1].get("created_at") or 0)
        except (TypeError, ValueError):
            return 0.0
    ents.sort(key=_t, reverse=True)
    page = ents[offset:offset + limit]
    return {"ok": True, "total": len(ents), "offset": offset, "limit": limit,
            "layer": layer or None,
            "items": [_card(n, e, cg.get(n)) for n, e in page]}


# 生效条件：node_id 去空白为空或 cg.get 返回 None（不存在或不可见，二者对调用方同形，不泄露存在性）→ {"ok":False,"error":"node_not_found"}；否则返回 {ok, id, content(全文), frontmatter, audit=auditview.build(cg, id, cap)}，audit 抛异常时 audit={"ok":False,"error":<类型: 消息>} 而非吞掉。
def node(cg, node_id, cap=8):
    nid = str(node_id or "").strip()
    rec = cg.get(nid) if nid else None
    if not rec:
        return {"ok": False, "error": "node_not_found", "id": nid,
                "hint": "找不到这条记忆，或当前身份看不到它。"}
    from .. import auditview
    try:
        audit = auditview.build(cg, nid, cap=cap)
    except Exception as exc:                                 # noqa: BLE001
        audit = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}
    return {"ok": True, "id": nid, "content": rec.get("content") or "",
            "frontmatter": rec.get("frontmatter") or {}, "audit": audit}


# 生效条件：limit 非数回落 100 并钳 [1, PAGE_MAX]；合并两路——cg.recent_events(limit) 的对话事件（kind="event"）与可见节点按 created_at 取最新 limit 条（kind="node"）——按时间 t 降序截 limit 条返回；recent_events 抛异常时如实带 events_error，节点路照常。
def timeline(cg, limit=100):
    try:
        limit = max(1, min(PAGE_MAX, int(limit)))
    except (TypeError, ValueError):
        limit = 100
    rows, err = [], None
    try:
        for r in cg.recent_events(limit=limit):
            rows.append({"kind": "event", "t": r.get("t"), "role": r.get("role"),
                         "text": _snip(r.get("text"), 400),
                         "tags": list(r.get("tags") or [])})
    except Exception as exc:                                 # noqa: BLE001
        err = "%s: %s" % (type(exc).__name__, exc)
    for c in browse(cg, limit=limit)["items"]:
        rows.append({"kind": "node", "t": c.get("created_at"), "id": c["id"],
                     "layer": c.get("layer"), "text": c.get("snippet"),
                     "tags": c.get("tags")})

    def _t(r):
        try:
            return float(r.get("t") or 0)
        except (TypeError, ValueError):
            return 0.0
    rows.sort(key=_t, reverse=True)
    return {"ok": True, "items": rows[:limit], "events_error": err}


# 生效条件：调用 cg.review_list()（MdCGSecure 版自带 op 闸与可见性过滤）并经 review_cli._kind_label/_brief 派生只读摘要（与 review_cli 索引同口径，不含正文全文）；AccessDenied 等异常 → {"ok":False,"error":"review_unavailable","detail":...}；按 created_at 升序（最久未裁决优先）。
def review(cg):
    from .. import review_cli
    try:
        recs = cg.review_list() or []
    except Exception as exc:                                 # noqa: BLE001
        return {"ok": False, "error": "review_unavailable",
                "detail": "%s: %s" % (type(exc).__name__, exc)}
    items = []
    for r in recs:
        items.append({"pid": r.get("pid"), "kind": review_cli._kind_label(r),
                      "status": r.get("status"), "layer": r.get("layer"),
                      "tags": list(r.get("tags") or []),
                      "created_at": r.get("created_at") or r.get("t"),
                      "summary": review_cli._brief(r, SNIPPET_MAX)})

    def _t(x):
        try:
            return float(x.get("created_at") or 0)
        except (TypeError, ValueError):
            return 0.0
    items.sort(key=_t)
    return {"ok": True, "items": items, "total": len(items),
            "hint": "首版只读：裁决请用 python -m md_cg.review_cli。"}


#: 关联记忆三圈（判据全部取自索引条目已有字段，白箱可查；同一条只落在最内的一圈）。
RELATED_TIERS = (
    ("inner", "内圈 · 强关联", "血缘：本条派生自它，或它派生自本条（derived_from）"),
    ("mid", "中圈 · 相关", "引用：本条引用它，或它引用本条（edges）"),
    ("outer", "外圈 · 弱相关", "共享标签（tags 交集非空，按共享数排序）"),
)


# 生效条件：node_id 去空白为空、不在索引或对当前身份不可见 → 与 node() 同形的 node_not_found（不泄露存在性）；否则只在可见条目（_visible_entries）里找三圈——inner：本条 derived_from 列出的父 + derived_from 含本条的子；mid：本条 edges 的 target + edges 指向本条的条目；outer：与本条 tags 交集非空的条目（按交集数降序、created_at 降序）；自身恒排除，跨圈去重（先到内圈者不再进外圈），每圈截 cap（缺省 8，非数回落 8 并钳 [1, PAGE_MAX]）并带 total/truncated；只对入选条目 cg.get 读正文。
def related(cg, node_id, cap=8):
    from .. import provenance
    try:
        cap = max(1, min(PAGE_MAX, int(cap)))
    except (TypeError, ValueError):
        cap = 8
    nid = str(node_id or "").strip()
    vis = dict(_visible_entries(cg))
    me = vis.get(nid) if nid else None
    if me is None:
        return {"ok": False, "error": "node_not_found", "id": nid,
                "hint": "找不到这条记忆，或当前身份看不到它。"}
    why = {"inner": {}, "mid": {}, "outer": {}}

    def _put(tier, oid, reason):
        if oid == nid or oid not in vis:
            return
        why[tier].setdefault(oid, []).append(reason)

    for par in provenance.as_list(me.get("derived_from")):
        _put("inner", str(par), "本条派生自它")
    for ed in me.get("edges") or []:
        if isinstance(ed, dict):
            _put("mid", str(ed.get("target")), "本条引用它（%s）" % (ed.get("relation_type") or "引用"))
    tags = set(me.get("tags") or [])
    for oid, oe in vis.items():
        if nid in [str(x) for x in provenance.as_list(oe.get("derived_from"))]:
            _put("inner", oid, "它派生自本条")
        for ed in oe.get("edges") or []:
            if isinstance(ed, dict) and str(ed.get("target")) == nid:
                _put("mid", oid, "它引用本条（%s）" % (ed.get("relation_type") or "引用"))
        shared = sorted(tags & set(oe.get("tags") or []))
        if shared:
            _put("outer", oid, "共享标签：" + "、".join(shared))
    for k in why["inner"]:
        why["mid"].pop(k, None)
        why["outer"].pop(k, None)
    for k in why["mid"]:
        why["outer"].pop(k, None)

    def _t(oid):
        try:
            return float(vis[oid].get("created_at") or 0)
        except (TypeError, ValueError):
            return 0.0
    tiers = []
    for key, label, rule in RELATED_TIERS:
        ids = list(why[key])
        if key == "outer":
            ids.sort(key=lambda o: (len(set(me.get("tags") or []) & set(vis[o].get("tags") or [])), _t(o)),
                     reverse=True)
        else:
            ids.sort(key=_t, reverse=True)
        items = []
        for oid in ids[:cap]:
            c = _card(oid, vis[oid], cg.get(oid))
            c["why"] = why[key][oid]
            items.append(c)
        tiers.append({"key": key, "label": label, "rule": rule, "items": items,
                      "total": len(ids), "truncated": len(ids) > cap})
    return {"ok": True, "id": nid, "tiers": tiers}


#: 显微镜可模拟的密级（restricted 是错误处置标记、不是身份档，不列入）。
SIM_CLEARANCES = ("public", "internal", "private", "secret")
#: 模拟身份的角色：平级记录单元（非设计者、非处置链路），另起一个会话。
SIM_ROLE = "recorder"


# 生效条件：sens 为 _readable 回填后的密级、sim 为模拟身份；仅在 _readable 已判「不可见」后调用，给出中文原因（判定本身不在此处）：sens 不在 SENSITIVITY_ORDER → 非法值隔离；== restricted → 处置链路限读；sim.allows(sens) 为假 → 密级高于身份；其余 → 会话绑定（private/secret 只对写入它的会话可见）。
def _hidden_reason(sens, sim):
    from ..security import SENSITIVITY_ORDER
    if sens not in SENSITIVITY_ORDER:
        return "密级值非法（%s），按隔离处理" % sens
    if sens == "restricted":
        return "错误处置标记：只有设计者 / 编排 / 核验角色能读"
    if not sim.allows(sens):
        return "密级 %s 高于这个身份的 %s" % (sens, sim.clearance)
    return "%s 记忆按会话绑定：只有写入它的那次会话能看到" % sens


# 生效条件：clearance 不在 SIM_CLEARANCES → {"ok":False,"error":"bad_clearance"}；先跑 search(cg, q, k=k)（record=False，失败原样返回）；再构造模拟身份 Principal(actor="console-sim", clearance, can_write=False, can_admin=False, role=SIM_ROLE, session=None→新会话)，对每条命中以 type(cg)._readable 绑定到 {principal: 模拟身份, _read: cg._read} 的代理上判可见（与库读隔离同一函数，传入条目副本，不改真索引）；cg 无 _readable → 全部记为可见并带 visibility_model=None 如实标出；返回每条 {..., sim_visible, hidden_reason} 与按资格四态 / 被挡计数，note 写明「逐条模拟、未以该身份重跑检索」。
def inspect(cg, q, clearance="internal", k=20):
    clearance = str(clearance or "internal").strip()
    if clearance not in SIM_CLEARANCES:
        return {"ok": False, "error": "bad_clearance",
                "hint": "可选密级：" + " / ".join(SIM_CLEARANCES)}
    res = search(cg, q, k=k)
    if not res.get("ok"):
        return res
    from types import SimpleNamespace
    from ..security import Principal
    sim = Principal(actor="console-sim", clearance=clearance, can_write=False,
                    can_admin=False, role=SIM_ROLE, auth_mode="local-ui")
    judge = getattr(type(cg), "_readable", None)
    proxy = SimpleNamespace(principal=sim, _read=getattr(cg, "_read", None))
    nodes = (cg.index or {}).get("nodes", {})
    counts = {"ACCEPT": 0, "DEFER": 0, "REJECT": 0, "BLINDSPOT": 0, "other": 0, "hidden": 0}
    for c in res["items"]:
        st = (c.get("qualification") or {}).get("state")
        counts[st if st in counts else "other"] += 1
        if not callable(judge):
            c["sim_visible"], c["hidden_reason"] = True, None
            continue
        e = dict(nodes.get(c["id"]) or {})
        try:
            ok = bool(judge(proxy, e))
        except Exception as exc:                             # noqa: BLE001 —— 判定异常 = 不可见
            ok, e["sensitivity"] = False, "<判定异常 %s>" % type(exc).__name__
        c["sim_visible"] = ok
        c["hidden_reason"] = None if ok else _hidden_reason(e.get("sensitivity"), sim)
        if not ok:
            counts["hidden"] += 1
    res.update({
        "clearance": clearance,
        "identity": {"clearance": clearance, "role": SIM_ROLE, "can_admin": False,
                     "session": "新会话（不是写入这些记忆的会话）"},
        "visibility_model": "MdCGSecure._readable" if callable(judge) else None,
        "counts": counts,
        "note": "可见性是对当前命中逐条模拟的，没有以该身份重跑检索；"
                "接近截断上限时，那个身份实际看到的排序可能不同（存疑）。",
    })
    return res
