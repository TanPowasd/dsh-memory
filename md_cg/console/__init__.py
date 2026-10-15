# -*- coding: utf-8 -*-
"""灵枢记忆控制台（本机只读网页）。

入口：``python -m md_cg.console``（Windows 双击 ``dsh/lingshu-console.bat``）。

边界（白箱声明）：
  · **只读**：数据面全部经 ``api`` 模块的纯读函数；身份恒 ``can_write=False``；
    没有任何写/遗忘/裁决路由（守卫 ``md_cg/test_console.py`` 以盘面逐字比对自证）。
  · **只听本机**：绑定 127.0.0.1，并校验 Host / Origin，防 DNS rebinding。
  · **不另起口径**：可见性走 ``MdCGSecure._readable``，节点详情走 ``auditview.build``，
    待复核走 ``review_list``——与 MCP 面同一实现。
"""
__all__ = ["api", "server"]
