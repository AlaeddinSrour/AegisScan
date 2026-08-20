import fs from 'node:fs'
import { exec } from 'node:child_process'
import serialize from 'node-serialize'

declare const User: any

export function commandInjection(req: any): void {
  const command = req.query.command
  exec(command)
}

export function pathTraversal(req: any): string {
  const filename = req.query.file
  return fs.readFileSync(filename, 'utf8')
}

export function codeInjection(req: any): unknown {
  const expression = req.body.expression
  return eval(expression)
}

export function unsafeDeserialization(req: any): unknown {
  const payload = req.body.payload
  return serialize.unserialize(payload)
}

export function objectAuthorizationCandidate(req: any): unknown {
  const userId = req.params.id
  return User.findByPk(userId)
}

export function reflectedXss(req: any, res: any): void {
  const html = req.query.html
  res.send(html)
}
