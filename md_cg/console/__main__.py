# -*- coding: utf-8 -*-
"""python -m md_cg.console —— 启动灵枢记忆控制台（本机只读网页）。"""
import sys

from .server import main

sys.exit(main())
