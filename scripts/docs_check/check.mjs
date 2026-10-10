#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import { fromMarkdown } from 'mdast-util-from-markdown'
import { toString } from 'mdast-util-to-string'
import GithubSlugger from 'github-slugger'

const EXTERNAL = new Set(['http:', 'https:', 'mailto:'])
const files = process.argv.slice(2)
const root = process.cwd()
let domain = false, ops = false, localChecks = 0, outOfScope = 0

function walk(node, visit) {
  if (!node || typeof node !== 'object') return
  if (visit(node)) return
  if (Array.isArray(node.children)) node.children.forEach((child) => walk(child, visit))
}

function badPercent(value) {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) === 0x25 && (i + 2 >= value.length || !/^[0-9A-Fa-f]{2}$/.test(value.slice(i + 1, i + 3)))) return true
  }
  return false
}

function schemeOf(url) {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:/.exec(url)
  return !m ? 'local' : EXTERNAL.has(url.slice(0, m[0].length)) ? 'external' : 'unsupported'
}

function buildIndex(tree) {
  const slugger = new GithubSlugger()
  const defs = new Map()
  const slugs = new Set()
  const links = []
  let html = false
  walk(tree, (node) => {
    if (node.type === 'heading') {
      slugs.add(slugger.slug(toString(node, { includeHtml: false, includeImageAlt: false })))
    } else if (node.type === 'definition') {
      if (!defs.has(node.identifier)) defs.set(node.identifier, node.url)
    } else if (node.type === 'html') {
      html = true
    }
    return false
  })
  walk(tree, (node) => {
    if (node.type === 'linkReference' || node.type === 'imageReference') {
      if (defs.has(node.identifier)) links.push(defs.get(node.identifier))
    } else if ((node.type === 'link' || node.type === 'image') && node.url) {
      links.push(node.url)
    }
    return false
  })
  return { slugs, links, html }
}

async function load(abs) {
  let st
  try {
    st = await stat(abs)
  } catch (err) {
    return err.code === 'ENOENT' ? { kind: 'missing' } : { kind: 'op', why: err.code || 'stat' }
  }
  if (!st.isFile()) return { kind: 'op', why: 'nonregular' }
  try {
    const text = await readFile(abs, 'utf8')
    return { kind: 'ok', index: buildIndex(fromMarkdown(text)) }
  } catch (err) {
    return { kind: 'op', why: err.code || 'parse' }
  }
}

function fail(marker, detail) {
  if (marker === 'DOCSLINK-OP-FAIL') ops = true
  else domain = true
  process.stderr.write(`${marker} ${detail}\n`)
  return true
}

async function validate(thisDoc, url, srcAbs) {
  const scheme = schemeOf(url)
  if (scheme === 'external') {
    outOfScope++
    process.stdout.write(`OUT-OF-SCOPE-EXTERNAL ${thisDoc} ${url}\n`)
    return false
  }
  if (scheme === 'unsupported') return fail('DOCSLINK-OP-FAIL', `${thisDoc} unsupported-scheme ${url}`)
  if (badPercent(url)) return fail('DOCSLINK-OP-FAIL', `${thisDoc} malformed-percent ${url}`)
  const rawPath = url.split('#')[0]
  const fragment = url.includes('#') ? url.slice(url.indexOf('#') + 1) : ''
  let decoded
  try { decoded = decodeURIComponent(rawPath) } catch {
    return fail('DOCSLINK-OP-FAIL', `${thisDoc} malformed-percent ${url}`)
  }
  const tgt = rawPath === '' ? srcAbs : path.resolve(path.dirname(srcAbs), decoded)
  const probe = await load(tgt)
  if (probe.kind === 'missing') return fail('DOCSLINK-MISSING', `${thisDoc} ${tgt}`)
  if (probe.kind === 'op') return fail('DOCSLINK-OP-FAIL', `${thisDoc} ${probe.why} ${tgt}`)
  if (fragment === '') {
    localChecks++
    return false
  }
  if (tgt !== srcAbs && !/\.md$/i.test(decoded)) return fail('DOCSLINK-OP-FAIL', `${thisDoc} unsupported-target ${url}`)
  const index = probe.index
  if (index.slugs.has(fragment)) {
    localChecks++
    return false
  }
  return index.html
    ? fail('DOCSLINK-OP-FAIL', `${thisDoc} html-anchor-unsupported ${url}`)
    : fail('DOCSLINK-MISSING-FRAGMENT', `${thisDoc} ${url}`)
}

let cleanDocs = 0
for (const f of files) {
  const abs = path.resolve(root, f)
  const probe = await load(abs)
  if (probe.kind === 'missing') { fail('DOCSLINK-MISSING', `${f} ${abs}`); continue }
  if (probe.kind === 'op') { fail('DOCSLINK-OP-FAIL', `${f} ${probe.why} ${abs}`); continue }
  const index = probe.index
  let failed = false
  for (const url of index.links) if (await validate(f, url, abs)) failed = true
  if (!failed) {
    cleanDocs++
    process.stdout.write(`DOCSLINK-OK ${f} (slugs ${index.slugs.size}, links ${index.links.length})\n`)
  }
}
const summary = `(files ${files.length}, clean ${cleanDocs}, local-checks ${localChecks}, out-of-scope ${outOfScope})`
if (ops) {
  process.stdout.write(`DOCSLINK-CHECK-RESULT ${summary}\n`)
  process.exit(2)
}
if (domain) {
  process.stdout.write(`DOCSLINK-CHECK-RESULT ${summary}\n`)
  process.exit(1)
}
process.stdout.write(`DOCSLINK-CHECK-OK ${summary}\n`)
process.exit(0)
