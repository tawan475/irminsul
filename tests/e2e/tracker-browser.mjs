// The browser half of the "Sign in with the tracker" end-to-end test
// (`src/signin/e2e.rs`, ignored by default; how to run it is in README.md
// next to this file). It plays the user in headless Chrome against a local
// tracker, so the real /link page and the real loopback callback meet.
//
//   node tracker-browser.mjs session <origin> <username> <password>
//       Signs up (or, when the name is taken, signs in) a made-up user.
//   node tracker-browser.mjs consent <authorize-link> <allow|cancel>
//       Opens irminsul's authorize link as that user, presses Allow or
//       Cancel and waits for the browser to land on irminsul's callback.
//   node tracker-browser.mjs api <origin> <METHOD> <path> [json-body]
//       A request from the signed-in browser (cookies + the CSRF header).
//   node tracker-browser.mjs page <url> <css-selector>
//       What a page shows once the selector has rendered.
//
// Every command prints one JSON line on stdout. The browser profile (and so
// the website sign-in) lives in IRMINSUL_E2E_PROFILE, a scratch directory the
// test makes and deletes. Puppeteer is not a dependency of this repository:
// IRMINSUL_E2E_PUPPETEER names a node_modules directory that has
// puppeteer-core, IRMINSUL_E2E_CHROME the Chrome executable.

import { createRequire } from 'node:module'
import path from 'node:path'

const env = (name) => {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is not set`)
  return value
}

const require = createRequire(path.join(env('IRMINSUL_E2E_PUPPETEER'), 'noop.js'))
const puppeteer = require('puppeteer-core')

// Cloudflare's always-pass Turnstile test secret accepts any token, and this
// is the one its test widget hands out.
const DUMMY_TURNSTILE = 'XXXX.DUMMY.TOKEN.XXXX'
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function withBrowser(run) {
  const browser = await puppeteer.launch({
    executablePath: env('IRMINSUL_E2E_CHROME'),
    headless: true,
    userDataDir: env('IRMINSUL_E2E_PROFILE'),
    args: ['--no-first-run', '--no-default-browser-check', '--disable-extensions'],
  })
  try {
    const page = await browser.newPage()
    try {
      return await run(page)
    } catch (error) {
      // Say where the browser was, for a failure that is the page's.
      const at = page.url()
      const text = await page
        .evaluate(() => document.body?.innerText ?? '')
        .catch(() => '')
      throw new Error(`${error?.message ?? error}\n  at page ${at}\n  showing: ${text.slice(0, 500)}`)
    }
  } finally {
    await browser.close()
  }
}

/** A JSON request from the page, as the app makes it. */
function call(page, method, url, body) {
  return page.evaluate(
    async (method, url, body) => {
      const headers = { 'x-gdt-csrf': '1' }
      if (body !== undefined) headers['content-type'] = 'application/json'
      const response = await fetch(url, {
        method,
        headers,
        credentials: 'same-origin',
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      const text = await response.text()
      let json = null
      try {
        json = JSON.parse(text)
      } catch {
        // Not JSON; the status says enough.
      }
      return { status: response.status, body: json }
    },
    method,
    url,
    body,
  )
}

async function session(origin, username, password) {
  return withBrowser(async (page) => {
    await page.goto(`${origin}/login`, { waitUntil: 'domcontentloaded' })
    const registered = await call(page, 'POST', '/api/auth/register', {
      username,
      password,
      turnstile: DUMMY_TURNSTILE,
    })
    if (registered.status < 300) return { ok: true, how: 'register' }
    const login = await call(page, 'POST', '/api/auth/login', {
      login: username,
      password,
      turnstile: DUMMY_TURNSTILE,
    })
    return { ok: login.status < 300, how: 'login', registered, login }
  })
}

async function consent(link, choice) {
  return withBrowser(async (page) => {
    await page.goto(link, { waitUntil: 'domcontentloaded' })
    // The SPA boots, checks the session and renders the consent card.
    await page.waitForSelector('form button[type="submit"]', { timeout: 30_000 })
    await sleep(1_000)
    const title = await page.$eval('form', (form) => form.innerText)
    if (choice === 'allow') {
      await page.click('form button[type="submit"]')
    } else {
      const buttons = await page.$$('form button[type="button"]')
      let pressed = false
      for (const button of buttons) {
        const text = await button.evaluate((b) => b.textContent.trim())
        if (text === 'Cancel') {
          await button.click()
          pressed = true
          break
        }
      }
      if (!pressed) throw new Error('no Cancel button')
    }
    // The page navigates to irminsul's loopback callback, which answers
    // once the code exchange is done.
    await page.waitForFunction(() => location.hostname === '127.0.0.1', { timeout: 30_000 })
    await page.waitForSelector('h1', { timeout: 30_000 })
    await sleep(500)
    const callback = new URL(page.url())
    return {
      ok: true,
      consent: title,
      callbackPath: callback.pathname,
      callbackParams: [...callback.searchParams.keys()].sort(),
      callbackError: callback.searchParams.get('error'),
      heading: await page.$eval('h1', (h) => h.textContent),
      text: await page.$eval('p', (p) => p.textContent),
    }
  })
}

/** What a page of the site shows once it has rendered (`selector`). */
async function show(url, selector) {
  return withBrowser(async (page) => {
    await page.goto(url, { waitUntil: 'domcontentloaded' })
    await page.waitForSelector(selector, { timeout: 30_000 })
    await sleep(1_500)
    return {
      ok: true,
      url: page.url(),
      text: await page.evaluate(() => document.body.innerText),
    }
  })
}

async function api(origin, method, apiPath, json) {
  return withBrowser(async (page) => {
    await page.goto(`${origin}/login`, { waitUntil: 'domcontentloaded' })
    const answer = await call(page, method, apiPath, json === undefined ? undefined : JSON.parse(json))
    return { ok: true, ...answer }
  })
}

// The test hands its arguments over as a JSON array in IRMINSUL_E2E_ARGS:
// on Windows a `node` shim (Volta, nvm) may re-run node through cmd.exe,
// which would split an authorize link at its `&`s.
const argv = process.env.IRMINSUL_E2E_ARGS
  ? JSON.parse(process.env.IRMINSUL_E2E_ARGS)
  : process.argv.slice(2)
const [command, ...args] = argv
const commands = { session, consent, api, page: show }
try {
  if (!commands[command]) throw new Error(`unknown command ${command}`)
  const result = await commands[command](...args)
  process.stdout.write(`${JSON.stringify(result)}\n`)
} catch (error) {
  process.stdout.write(`${JSON.stringify({ ok: false, error: String(error?.stack ?? error) })}\n`)
  process.exitCode = 1
}
