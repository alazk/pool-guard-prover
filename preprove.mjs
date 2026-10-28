// Proves ahead of time, through the console's API, everything a visitor can ask for on the SP1
// route: every listed wallet's set deposits and its listing (swaps and withdrawals), and the
// off-list wallets' set deposits. A proof already made is skipped by the console, so this is safe
// to run again; run it after editing the sheet, or before an event. The prover repo runs it daily.
//
// Then it resets the demo wallets whose room is used up (the console keeps each one's largest set
// amount free, so its proven answers stay true): it withdraws what each holds, through Newton and
// the hook like any visitor, and recounts the wallet's row once the withdrawals have landed.
// RESET=0 skips that part.
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

// the nightly reset of full demo wallets
async function reset(body) {
  const r = await fetch(`${SITE}/api/prove`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${SECRET}` }, body: JSON.stringify(body), signal: AbortSignal.timeout(60_000) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
  return j;
}
let resetFailed = 0, resetCount = 0;
if (process.env.RESET !== '0' && SECRET) {
  const { wallets } = await reset({ reset: 'plan' });
  console.log(wallets.length ? `${wallets.length} demo wallets have used their room; resetting them` : 'no demo wallet needs a reset');
  const done = [];
  for (const w of wallets) {
    try {
      // a wallet whose deposits sit in more than one position takes one withdrawal each
      const hashes = [];
      for (let k = 0; k < 4; k++) { const r = await reset({ reset: w.id }); if (r.empty) break; hashes.push(r.hash); console.log(`  ${w.id} ${w.address.slice(0, 10)}…: withdrew ${Number(r.amount).toLocaleString('en-US')}, ${r.explorer}`); if (!r.more) break; await new Promise((ok) => setTimeout(ok, 20_000)); }
      done.push({ ...w, hashes });
    } catch (e) { resetFailed++; console.log(`  ${w.id}: ${e.message}`); }
  }
  if (done.length) {
    // the withdrawals land in a block or two; then each row is recounted from the chain
    await new Promise((ok) => setTimeout(ok, 45_000));
    for (const w of done) {
      try {
        // each withdrawal settles from its receipt, which writes the row; a slow block gets a second try
        for (const hash of w.hashes) { for (let k = 0; ; k++) { try { await reset({ reset: w.id, recount: true, hash }); break; } catch (e) { if (k >= 3 || !/not landed/.test(e.message)) throw e; await new Promise((ok) => setTimeout(ok, 20_000)); } } }
        if (!w.hashes.length) await reset({ reset: w.id, recount: true });
      } catch (e) { resetFailed++; console.log(`  ${w.id} recount: ${e.message}`); }
    }
    resetCount = done.length;
    console.log(`reset ${done.length} wallets`);
  }
}
// one line to read at a glance, also on the run's summary page when this runs in Actions
const status = `${made}/${plan.items.length} proofs ready${started ? `, ${started} being made` : ''}${failed ? `, ${failed} failed` : ''}; ${resetCount} wallets reset${resetFailed ? `, ${resetFailed} reset steps failed` : ''}`;
console.log(`STATUS ${status}`);
if (process.env.GITHUB_STEP_SUMMARY) { try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `**Pool Guard proofs:** ${status}\n`); } catch {} }
process.exit(failed || resetFailed ? 1 : 0);
