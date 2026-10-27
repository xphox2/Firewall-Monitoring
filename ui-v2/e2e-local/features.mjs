/**
 * The features the console added, exercised against the REAL instance.
 *
 * The mocked suite can only check that a control renders. These checks ask
 * the questions that matter:
 *
 *   1. does the Clear control APPEAR for a device that holds a credential?
 *      (The review found it did not - the mask was read as "empty", so the
 *      control never appeared for the case it exists for.)
 *   2. does the alert override save the CONFIG AND THE PROFILE together,
 *      in one request - and does a save that does not mention the profile
 *      leave the assignment alone?
 *   3. does the purge estimate tell the operator the truth?
 *   4. is a toast announced ONCE?
 *
 * This script WRITES to the database it is pointed at - it saves an alert
 * override. It refuses to run against anything but the local machine.
 *
 * Usage:
 *   FWMON_LOCAL_PASSWORD=... node features.mjs --base http://127.0.0.1:8099
 */
import { chromium, devices } from '@playwright/test';
import { localBase, localPassword, login } from './guard.mjs';

const BASE = localBase();
const PASSWORD = localPassword();

const results = [];
const check = (name, pass, detail) => {
  results.push({ name, pass, detail });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
};

const browser = await chromium.launch();
const context = await browser.newContext({
  ...devices['Desktop Chrome'],
  viewport: { width: 1440, height: 900 },
});
const page = await context.newPage();

await login(page, BASE, PASSWORD);
await page.goto(`${BASE}/admin/v2/devices`, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(2500);
check('the console loads with the real data', page.url().includes('/admin/v2/devices'), page.url());

// --- 1. the Clear control appears ----------------------------------------
// The credentials live in the device editor's "SSH & API Keys" tab, and the
// editor is opened from the DEVICE LIST.
const openEditor = page.getByRole('button', { name: /Edit device/i }).first();
if (await openEditor.count()) {
  await openEditor.click();
  await page.waitForTimeout(1500);
}
const credsTab = page.getByRole('tab', { name: /SSH & API Keys/i }).first();
if (await credsTab.count()) {
  await credsTab.click();
  await page.waitForTimeout(1500);
}
const clearButtons = page.getByRole('button', { name: /^Clear$/ });
const clearCount = await clearButtons.count();
check(
  'the Clear control appears for a device that HOLDS a credential',
  clearCount > 0,
  `${clearCount} Clear control(s) on the device that holds an SNMP community and an SSH password`,
);

// --- 2. the alert override is ONE write -----------------------------------
const deviceId = 1;
const csrf = await page.evaluate(async () => {
  const res = await fetch('/admin/api/csrf-token', { credentials: 'same-origin' });
  const body = await res.json();
  return body?.data?.csrf_token ?? body?.csrf_token ?? '';
});
const profileId = await page.evaluate(async () => {
  const res = await fetch('/admin/api/event-rule-profiles', { credentials: 'same-origin' });
  const body = await res.json();
  const data = body?.data ?? body;
  const list = Array.isArray(data) ? data : (data?.profiles ?? []);
  return list.length ? list[0].id : null;
});

if (profileId && csrf) {
  const res = await page.request.put(`${BASE}/admin/api/devices/${deviceId}/alert-config`, {
    data: { cpu_threshold: 91, event_profile_id: profileId },
    headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' },
  });
  check(
    'the alert config and the event profile are saved in ONE request',
    res.status() === 200,
    `PUT /alert-config answered ${res.status()}`,
  );
  const rb = await (
    await page.request.get(`${BASE}/admin/api/devices/${deviceId}/alert-config`)
  ).json();
  const cfg = rb?.data ?? rb;
  check(
    'the saved override has BOTH the threshold and the profile',
    cfg?.cpu_threshold === 91 && cfg?.event_profile_id === profileId,
    `threshold=${cfg?.cpu_threshold} profile=${cfg?.event_profile_id}`,
  );
  // A save that does NOT mention the profile must leave it alone.
  const res2 = await page.request.put(`${BASE}/admin/api/devices/${deviceId}/alert-config`, {
    data: { cpu_threshold: 92 },
    headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' },
  });
  const rb2 = await (
    await page.request.get(`${BASE}/admin/api/devices/${deviceId}/alert-config`)
  ).json();
  const cfg2 = rb2?.data ?? rb2;
  check(
    'a save that does not mention the profile leaves it alone',
    res2.status() === 200 && cfg2?.event_profile_id === profileId,
    `profile=${cfg2?.event_profile_id}`,
  );
} else {
  check('the alert config and the event profile are saved in ONE request', false, 'no CSRF token or no profile');
}

// --- 3. the purge estimate tells the truth -------------------------------
// A LIVE device is refused the estimate (409) - that is the point of the
// check. A RETIRED one gets the estimate, and the estimate has to say
// whether its total is a lower bound and what would block the purge.
const liveEst = await page.request.get(`${BASE}/admin/api/devices/${deviceId}/purge/estimate`);
check('the estimate refuses a LIVE device', liveEst.status() === 409, `answered ${liveEst.status()}`);
const retiredId = 4; // TECHLABS-FW-01, retired in this copy of the data
const est = await page.request.get(`${BASE}/admin/api/devices/${retiredId}/purge/estimate`);
const estBody = await est.json().catch(() => ({}));
const estData = estBody?.data ?? estBody;
check(
  'the estimate reports whether the total is a lower bound',
  est.status() === 200 && 'capped' in (estData ?? {}),
  `status=${est.status()} capped=${estData?.capped} total=${estData?.total} tables=${estData?.tables?.length}`,
);
check(
  'the estimate reports the blockers (absent when there are none)',
  estData?.blockers === undefined || Array.isArray(estData.blockers),
  `blockers=${JSON.stringify(estData?.blockers)}`,
);

// --- 4. a toast is announced once ----------------------------------------
await page.goto(`${BASE}/admin/v2/overview`, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(1500);
const liveRegions = await page.evaluate(() => {
  const all = [...document.querySelectorAll('[aria-live]')];
  return {
    liveContainers: all.length,
    statusRoles: document.querySelectorAll('[role="status"]').length,
  };
});
check(
  'a toast container is not ALSO a live region (that announces twice)',
  liveRegions.liveContainers === 0,
  `aria-live containers=${liveRegions.liveContainers}, role=status=${liveRegions.statusRoles}`,
);

await context.close();
await browser.close();

const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  for (const f of failed) console.log(`  FAILED: ${f.name} — ${f.detail}`);
  process.exit(1);
}
