// Real-browser CSP + functional test for alea-web-offline.html.
// Loads the file:// page in headless Chromium, captures ALL console messages
// (a wrong CSP script-hash would surface as a CSP violation and the script
// would never run), asserts ZERO network requests, then drives each feature
// through the actual DOM and checks the rendered results.
import { createRequire } from "node:module";
import path from "node:path";

// playwright-core is resolved from node_modules relative to this file — it is
// NOT vendored. One-time setup (from web/):
//   npm i --no-save playwright-core && npx playwright-core install chromium
// Alternatively set ALEA_CHROMIUM_PATH to any Chromium/Chrome binary.
const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require("playwright-core"));
} catch {
  console.log("SKIP: playwright-core not installed — this browser harness needs it.");
  console.log("      From web/:  npm i --no-save playwright-core && npx playwright-core install chromium");
  process.exit(0);
}

const htmlPath = path.resolve(process.argv[2] || "alea-web-offline.html");
const url = "file://" + htmlPath;

// Browser resolution order: ALEA_CHROMIUM_PATH override -> Playwright-managed
// Chromium (respects PLAYWRIGHT_BROWSERS_PATH) -> system Chrome channel.
async function launchChromium() {
  const opts = { headless: true };
  if (process.env.ALEA_CHROMIUM_PATH) {
    return chromium.launch({ ...opts, executablePath: process.env.ALEA_CHROMIUM_PATH });
  }
  try {
    return await chromium.launch(opts);
  } catch {
    try {
      return await chromium.launch({ ...opts, channel: "chrome" });
    } catch {
      console.log("SKIP: no Chromium available. Run `npx playwright-core install chromium`");
      console.log("      (from web/, after `npm i --no-save playwright-core`), or set");
      console.log("      ALEA_CHROMIUM_PATH to a Chromium/Chrome executable.");
      process.exit(0);
    }
  }
}
const browser = await launchChromium();
const ctx = await browser.newContext();
const page = await ctx.newPage();

const consoleMsgs = [];
const cspViolations = [];
const networkURLs = [];
page.on("console", (m) => consoleMsgs.push(`[${m.type()}] ${m.text()}`));
page.on("pageerror", (e) => consoleMsgs.push(`[pageerror] ${e.message}`));
page.on("request", (r) => {
  if (r.url() !== url) networkURLs.push(r.url());
});
// CSP violations surface as console errors AND securitypolicyviolation events.
await page.addInitScript(() => {
  document.addEventListener("securitypolicyviolation", (e) => {
    // eslint-disable-next-line no-console
    console.error("CSP-VIOLATION " + e.violatedDirective + " " + e.blockedURI);
  });
});

await page.goto(url, { waitUntil: "load" });
await page.waitForTimeout(400); // let boot() + wasm instantiate

let failures = 0;
function check(name, cond, detail) {
  if (!cond) failures++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  -- " + (detail || "")}`);
}

// 1. The script actually ran under CSP: dismiss the disclosure, then confirm
//    the wasm booted (no boot-error text).
console.log("CSP / boot:");
const bootErr = await page.$eval("#boot-error", (el) => el.textContent || "");
check("no boot error", bootErr === "", bootErr);
// The ONLY expected CSP notice is the mandated `data:,` favicon hitting
// img-src 'none' (SPEC_WEB_OFFLINE §3.3: exact CSP keeps img-src 'none' AND
// <link rel=icon href="data:,"> to suppress the favicon fetch — the block IS
// the suppression; zero network requests result). Any OTHER violation
// (script-src / style-src / connect-src / …) is a real failure.
const isFaviconNotice = (m) =>
  /img-src/.test(m) && /data:,|data:'|\bdata\b/.test(m) && /image/i.test(m + " image") ;
const cspErrs = consoleMsgs.filter(
  (m) =>
    /CSP-VIOLATION|Content Security Policy|Refused to/.test(m) &&
    !(/img-src/.test(m) && /data:/.test(m)) &&
    !/CSP-VIOLATION img-src data/.test(m)
);
check("no CSP violations (except mandated data: favicon)", cspErrs.length === 0, cspErrs.join(" | "));
void isFaviconNotice;
check("zero external network requests", networkURLs.length === 0, networkURLs.join(", "));

// 2. Disclosure modal present, dismissable.
const modalVisible = await page.$eval("#disclosure", (el) => !el.hasAttribute("hidden"));
check("first-run disclosure shown", modalVisible);
await page.click("#disclosure-ok");
const modalHidden = await page.$eval("#disclosure", (el) => el.hasAttribute("hidden"));
check("disclosure dismissable", modalHidden);

// 3. Feature 1 — rehearsal.
console.log("Feature 1 — rehearsal:");
await page.click("#reh-run");
await page.waitForTimeout(50);
const rehText = await page.$eval("#reh-out", (el) => el.textContent);
check("rehearsal shows abandon…about", /abandon abandon abandon.*about/.test(rehText));
check("rehearsal BIP84 anchor", rehText.includes("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
check("rehearsal PUBLIC TEST watermark", rehText.includes("PUBLIC TEST"));

// 4. Feature 2 — verify (own mnemonic never echoed).
console.log("Feature 2 — verify:");
await page.click('[data-target="p-ver"]');
await page.fill("#ver-mnemonic", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
await page.click("#ver-run");
await page.waitForTimeout(50);
const verText = await page.$eval("#ver-out", (el) => el.textContent);
check("verify BIP84 anchor", verText.includes("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
check("verify fingerprint", verText.includes("73c5da0a"));
check("verify does NOT echo mnemonic", !/abandon abandon abandon/.test(verText));

// 4b. Feature 2b — more derivation options (grid) on the Verify tab.
console.log("Feature 2b — more derivation options:");
await page.click("#ver-more > summary"); // expand the <details>
await page.selectOption("#grid-std", "2"); // BIP84
await page.fill("#grid-account", "0");
await page.selectOption("#grid-change", "0");
await page.fill("#grid-start", "0");
await page.fill("#grid-count", "5");
await page.click("#grid-run");
await page.waitForTimeout(50);
const gridText = await page.$eval("#grid-out", (el) => el.textContent);
const gridRows = await page.$$eval("#grid-out .gridtbl tbody tr", (rows) => rows.length);
check("grid renders 5 address rows", gridRows === 5, "rows=" + gridRows);
check("grid index0 == BIP84 anchor", gridText.includes("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
check("grid index1 == published vector", gridText.includes("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"));
check("grid fingerprint shown", gridText.includes("73c5da0a"));
check("grid does NOT echo mnemonic", !/abandon abandon abandon/.test(gridText));
check("grid same-seed explainer present", /additional derivation paths of the SAME seed/.test(gridText));

// 5. Feature 3 — compat (hex).
console.log("Feature 3 — compat:");
await page.click('[data-target="p-cmp"]');
await page.selectOption("#cmp-enc", "4"); // hex
await page.fill("#cmp-input", "00000000000000000000000000000000");
await page.click("#cmp-run");
await page.waitForTimeout(50);
const cmpText = await page.$eval("#cmp-out", (el) => el.textContent);
check("compat reproduces abandon…about", /abandon abandon abandon.*about/.test(cmpText));
check("compat BIP84 anchor", cmpText.includes("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
check("compat foreign-material watermark", /REPRODUCTION OF FOREIGN MATERIAL/.test(cmpText));

// 6. Integrity — self-hash.
console.log("Integrity — self-hash:");
await page.click('[data-target="p-int"]');
await page.click("#selfhash-run");
await page.waitForTimeout(50);
const hash = await page.$eval("#selfhash", (el) => el.textContent);
check("self-hash is 64 hex chars", /^[0-9a-f]{64}$/.test(hash), hash);

console.log(`\n${failures === 0 ? "ALL BROWSER CHECKS PASSED" : failures + " CHECK(S) FAILED"}`);
await browser.close();
process.exit(failures === 0 ? 0 : 1);
