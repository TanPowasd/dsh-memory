import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

// 守卫：`lingshu console` 真的拉起 python -m md_cg.console（包根进 PYTHONPATH、参数直通、退出码回传），
// 且对不存在的记忆库如实报错退出 2、不建目录。变异自证：把 cli.ts 的 console 分支删掉 ⇒ 打印 USAGE 退 1 ⇒ 红。
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const CLI = join(REPO, 'lib', 'cli.js')

test('lingshu console：不存在的 --root → 退出码 2 + 中文原因 + 不建目录', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'lsconsole-'))
  const ghost = join(tmp, 'no_such_root')
  try {
    const py = process.env.MDCG_PYTHON || (process.platform === 'win32' ? 'python' : 'python3')
    const r = spawnSync(process.execPath, [CLI, 'console', '--root', ghost, '--no-browser'],
      { encoding: 'utf8', timeout: 60000, env: { ...process.env, MDCG_PYTHON: py }, cwd: tmp })
    const out = (r.stdout ?? '') + (r.stderr ?? '')
    assert.equal(r.status, 2, out)
    assert.match(out, /打不开记忆库/)
    assert.equal(existsSync(ghost), false)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})
