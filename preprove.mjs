// Proves ahead of time, through the console's API, everything a visitor can ask for on the SP1
// route: every listed wallet's set deposits and its listing (swaps and withdrawals), and the
// off-list wallets' set deposits. A proof already made is skipped by the console, so this is safe
// to run again; run it after editing the sheet, before an event, and every two weeks.
//   node engine/preprove.mjs                       against https://newton-pool-guard.vercel.app
//   SITE_URL=http://localhost:3078 node engine/preprove.mjs
//
// The site returns the list; this asks for each proof in turn (one function call cannot dispatch
// them all within its time limit). On the free prover each new proof is one GitHub Actions run of
// 20 to 35 minutes, up to 20 at once, so a first full run takes a couple of hours.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const SITE = (process.env.SITE_URL || 'https://newton-pool-guard.vercel.app').replace(/\/$/, '');
// the site's CRON_SECRET (cronSecret in the accounts file), so these requests are not rate limited
const SECRET = process.env.CRON_SECRET || (() => { try { return JSON.parse(fs.readFileSync(path.join(os.homedir(), '.newton-hook.accounts.json'), 'utf8')).cronSecret || ''; } catch { return ''; } })();
if (!SECRET) console.log('no cronSecret in ~/.newton-hook.accounts.json: the site will rate limit these requests');
async function api(body) {
  for (let i = 0; ; i++) {
    try {
      const r = await fetch(`${SITE}/api/prove`, { method: 'POST', headers: { 'content-type': 'application/json', ...(SECRET ? { authorization: `Bearer ${SECRET}` } : {}) }, body: JSON.stringify(body), signal: AbortSignal.timeout(60_000) });
      const j = await r.json().catch(() => ({}));
      if (r.ok) return j;
      if (r.status < 500 || i >= 2) throw new Error(j.error ?? `HTTP ${r.status}`);
    } catch (e) { if (i >= 2) throw e; }
    await new Promise((ok) => setTimeout(ok, 3000 * (i + 1)));
  }
}
const plan = await api({ plan: true });
console.log(`${SITE}: ${plan.wallets} listed wallets and ${plan.outside} off the list, ${plan.items.length} proofs to have`);
let made = 0, started = 0, failed = 0;
for (const [n, it] of plan.items.entries()) {
  try { const x = await api({ address: it.wallet, amount: it.amount }); x.cached ? made++ : started++; }
  catch (e) { failed++; console.log(`  ${it.wallet} ${it.amount}: ${e.message}`); }
  if ((n + 1) % 20 === 0 || n + 1 === plan.items.length) console.log(`  ${n + 1}/${plan.items.length}: ${made} already made, ${started} started, ${failed} failed`);
}
console.log(started ? `${started} proofs are being made on the prover; they appear on its proofs release as each run finishes.` : 'every proof is made.');
process.exit(failed ? 1 : 0);
