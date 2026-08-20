import fs from 'node:fs'
import { execFile } from 'node:child_process'

declare const User: any

export function safeCommand(): void {
  execFile('/usr/bin/uptime', [])
}

export function safePath(): string {
  return fs.readFileSync('/srv/app/public/status.txt', 'utf8')
}

export function safeParsing(req: any): unknown {
  return JSON.parse(req.body.payload)
}

export function currentUser(req: any): unknown {
  return User.findByPk(req.user.id)
}

export function safeResponse(req: any, res: any): void {
  res.send(escapeHtml(req.query.html))
}

declare function escapeHtml(value: string): string
