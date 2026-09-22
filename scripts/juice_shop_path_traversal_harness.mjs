#!/usr/bin/env node
import assert from 'node:assert/strict'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { registerHooks } from 'node:module'
import { mock } from 'node:test'
import { pathToFileURL } from 'node:url'

if (!process.argv[2]) throw new Error('Pass the Juice Shop checkout path')
const root = path.resolve(process.argv[2])
if (!fs.statSync(root).isDirectory()) throw new Error('Pass the Juice Shop checkout path')
const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim()
const commit = git('rev-parse', 'HEAD')
assert.equal(commit, '5658473cf8814459bf89000ce373b20ed0b4eb37', 'Unexpected benchmark revision')
assert.equal(git('status', '--porcelain'), '', 'The benchmark checkout must be clean')
const hash = data => createHash('sha256').update(data).digest('hex')
const sourceHashes = Object.fromEntries([
  'routes/vulnCodeFixes.ts', 'routes/vulnCodeSnippet.ts', 'lib/codingChallenges.ts'
].map(file => [file, hash(fs.readFileSync(path.join(root, file)))]))
process.chdir(root)

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'js-yaml') {
      return { url: 'data:text/javascript,export%20const%20load%3D()%3D%3E(%7Bfixes%3A%5B%7Bid%3A1%2Cexplanation%3A%22ok%22%7D%5D%2Chints%3A%5B%5D%7D)%3Bexport%20default%20%7Bload%7D', shortCircuit: true }
    }
    if (specifier === 'express' || specifier === '@juice-shop/models/challenge') {
      return { url: 'data:text/javascript,export%20%7B%7D', shortCircuit: true }
    }
    if ((specifier.startsWith('../') || specifier.startsWith('./')) && context.parentURL) {
      const candidate = new URL(specifier + '.ts', context.parentURL)
      if (fs.existsSync(candidate)) return { url: candidate.href, shortCircuit: true }
    }
    return nextResolve(specifier, context)
  }
})

const url = relative => pathToFileURL(path.join(root, relative)).href
const calls = []
const original = {
  existsSync: fs.existsSync,
  readdirSync: fs.readdirSync,
  readFileSync: fs.readFileSync,
  stat: fsp.stat,
  readFile: fsp.readFile
}
fs.existsSync = target => { calls.push(['existsSync', String(target)]); return original.existsSync(target) }
fs.readdirSync = (...args) => { calls.push(['readdirSync', String(args[0])]); return original.readdirSync(...args) }
fs.readFileSync = (...args) => { calls.push(['readFileSync', String(args[0])]); return original.readFileSync(...args) }
fsp.stat = async target => { calls.push(['stat', String(target)]); return original.stat(target) }
fsp.readFile = async (...args) => { calls.push(['readFile', String(args[0])]); return original.readFile(...args) }

await mock.module(url('lib/accuracy.ts'), { namedExports: {
  getFindItAttempts: () => 0, storeFixItVerdict: () => {}, storeFindItVerdict: () => {}
} })
await mock.module(url('lib/challengeUtils.ts'), { namedExports: { solveFixIt: async () => {}, solveFindIt: async () => {} } })
await mock.module(url('lib/utils.ts'), { namedExports: { getErrorMessage: error => String(error) } })
const builderWarnings = []
await mock.module(url('lib/logger.ts'), { defaultExport: { warn: message => builderWarnings.push(message) } })

const knownKey = 'loginAdminChallenge'

const fixes = await import(url('routes/vulnCodeFixes.ts'))
const snippets = await import(url('routes/vulnCodeSnippet.ts'))
const { getCodeChallenges } = await import(url('lib/codingChallenges.ts'))
// Execute the original map builder against real repository sources. Its expected
// source discovery reads are setup, separate from handler metadata reads.
const challengeMap = await getCodeChallenges()
assert.ok(challengeMap.has(knownKey))
assert.equal(builderWarnings.length, 0, 'Challenge discovery must not silently skip sources')
assert.equal([...challengeMap.keys()].some(key => /[/\\]|\.\./.test(key)), false)

const response = () => ({
  statusCode: null, body: undefined,
  status(code) { this.statusCode = code; return this },
  json(body) { this.body = body; return this },
  __(text) { return text }
})
const next = error => { if (error) throw error }

const inputs = [
  knownKey,
  '../outside', '../../outside', '..\\outside', '%2e%2e%2foutside',
  '%252e%252e%252foutside', '../outside\u0000',
  'loginAdminChallenge/../../../outside', 'loginAdminChallenge\\..\\..\\outside',
  '/tmp/outside', '..//outside', './../../../outside', '__proto__', 'constructor',
  'toString', 'hasOwnProperty', 'valueOf', 'prototype',
  null, [], {}, 0, true, [knownKey], [knownKey, '../outside'], ['../outside'], { toString: '../outside' },
  knownKey
]
const results = []
for (const phase of ['first-pass', 'cached-repeat']) {
for (const key of inputs) {
  calls.length = 0
  const resFix = response()
  let fixError = null
  try {
    await fixes.checkCorrectFix()({ body: { key, selectedFix: 0 } }, resFix, next)
  } catch (error) { fixError = error.constructor.name }
  const fixCalls = [...calls]

  calls.length = 0
  const resSnippet = response()
  let snippetError = null
  try {
    await snippets.checkVulnLines()({ body: { key, selectedLines: [] } }, resSnippet, next)
  } catch (error) { snippetError = error.constructor.name }
  const snippetCalls = [...calls]
  results.push({ phase, key, fix: { status: resFix.statusCode, error: fixError, body: resFix.body, calls: fixCalls },
    snippet: { status: resSnippet.statusCode, error: snippetError, body: resSnippet.body, calls: snippetCalls } })
}
}

const boundary = path.resolve(root, 'data/static/codefixes')
const unsafe = (target, base = boundary) => {
  const resolved = path.resolve(root, String(target))
  return resolved !== base && !resolved.startsWith(base + path.sep)
}
for (const result of results) {
  for (const side of [result.fix, result.snippet]) {
    assert.equal(side.calls.some(([, target]) => unsafe(target)), false,
      `filesystem escape observed for ${JSON.stringify(result.key)}`)
  }
}
for (const result of results) {
  const fixValid = result.key === knownKey || (Array.isArray(result.key) && result.key.length === 1 && result.key[0] === knownKey)
  const prototypeKey = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf'].includes(result.key)
  const coercionError = result.key !== null && !Array.isArray(result.key) && typeof result.key === 'object' && Object.hasOwn(result.key, 'toString')
  assert.equal(result.fix.calls.some(([kind]) => kind === 'readFileSync'), fixValid)
  assert.equal(result.fix.error, prototypeKey || coercionError ? 'TypeError' : null)
  assert.equal(result.fix.status, prototypeKey || coercionError ? null : fixValid ? 200 : 404)
  assert.equal(result.snippet.calls.some(([kind]) => kind === 'readFile'), result.key === knownKey)
  assert.equal(result.snippet.error, null)
  assert.equal(result.snippet.status, result.key === knownKey || coercionError ? 200 : 404)
}
for (const result of results.filter(item => item.key === knownKey)) {
  assert.equal(result.fix.error, null)
  assert.equal(result.snippet.error, null)
  assert.equal(result.fix.status, 200)
  assert.equal(result.snippet.status, 200)
}

// Independent controls actually read a harmless sentinel outside a temporary
// allowed directory. No files are created in the pinned repository.
const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'aegisscan-path-control-'))
const allowed = path.join(sandbox, 'allowed')
fs.mkdirSync(allowed)
const sentinel = path.join(sandbox, 'outside.info.yml')
fs.writeFileSync(sentinel, 'harmless path traversal sentinel\n')
const vulnerable = key => fs.readFileSync(path.join(allowed, key + '.info.yml'), 'utf8')
const guarded = key => /^[A-Za-z0-9_-]+$/.test(key) ? vulnerable(key) : null
calls.length = 0
assert.equal(vulnerable('../outside'), 'harmless path traversal sentinel\n')
assert.equal(calls.some(([, target]) => unsafe(target, allowed)), true)
const positiveControlCalls = [...calls]
calls.length = 0
assert.equal(guarded('../outside'), null)
assert.equal(calls.length, 0)
fs.writeFileSync(path.join(allowed, 'valid.info.yml'), 'valid control\n')
assert.equal(guarded('valid'), 'valid control\n')
assert.equal(calls.some(([, target]) => unsafe(target, allowed)), false)
assert.equal(git('status', '--porcelain'), '', 'Harness modified checkout')

console.log(JSON.stringify({
  repository: root,
  commit, node_version: process.version, generated_at: new Date().toISOString(),
  source_sha256: sourceHashes,
  harness_sha256: hash(original.readFileSync(new URL(import.meta.url))),
  test: 'original handlers with mocked collaborators and traced real filesystem APIs',
  limitations: ['Handler-level tests, not HTTP or production deployment tests.',
    'Original challenge-map builder runs before requests; map is initialized for all test requests.',
    'YAML parser, accuracy, challenge side effects, logger, error formatter, and HTTP response are stubbed.',
    'No symlink mutation, filesystem races, global prototype pollution, or hostile repository source changes are simulated.'],
  challenge_keys: [...challengeMap.keys()].sort(),
  inputs: results,
  controls: { vulnerable_escape_detected: true, guarded_escape_blocked: true,
    guarded_valid_read_passed: true, positive_control_calls: positiveControlCalls },
  summary: { handler_invocations: results.length * 2,
    fix_handler_exceptions: results.filter(item => item.fix.error !== null).length,
    outside_handler_reads: 0 },
  conclusion: 'No tested input reached a filesystem read outside the intended directory.'
}, null, 2))
