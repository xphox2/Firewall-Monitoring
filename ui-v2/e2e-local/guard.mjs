/**
 * The guard every script in this folder shares.
 *
 * These scripts drive the REAL console against a copy of the production
 * database. The features script WRITES to that copy (it saves an alert
 * override), so it must never be pointed at production: a stray run would
 * change a live device's alert configuration, and the walk would hammer
 * the production API with a browser.
 *
 * A base URL that is not the local machine is refused outright.
 */

/** The local addresses these scripts are allowed to drive. */
const LOCAL_HOSTS = ['127.0.0.1', 'localhost', '::1', '[::1]'];

/**
 * Parse the arguments and return the base URL, refusing anything that is
 * not the local machine.
 */
export function localBase(argv = process.argv.slice(2)) {
  const i = argv.indexOf('--base');
  const base = i >= 0 && argv[i + 1] ? argv[i + 1] : 'http://127.0.0.1:8099';
  let host;
  try {
    host = new URL(base).hostname;
  } catch {
    throw new Error(`--base is not a URL: ${base}`);
  }
  if (!LOCAL_HOSTS.includes(host)) {
    throw new Error(
      `refusing to drive ${base}: these scripts act on the database they are pointed at, ` +
        `and they are only safe against a LOCAL copy. Point --base at 127.0.0.1.`,
    );
  }
  return base.replace(/\/$/, '');
}

/** The password for the local admin, from the environment. */
export function localPassword(argv = process.argv.slice(2)) {
  const i = argv.indexOf('--password');
  if (i >= 0 && argv[i + 1]) return argv[i + 1];
  const env = process.env.FWMON_LOCAL_PASSWORD;
  if (!env) {
    throw new Error(
      'no password: set FWMON_LOCAL_PASSWORD, or pass --password. ' +
        'The local admin password is printed by "fwmon-api reset-auth --user admin" ' +
        'against the local instance.',
    );
  }
  return env;
}

/** Log in through the real login form. */
export async function login(page, base, password) {
  await page.goto(`${base}/admin/login`, { waitUntil: 'domcontentloaded' });
  await page.fill('#username', 'admin');
  await page.fill('#password', password);
  await page.click('#login-btn');
  await page.waitForTimeout(1500);
  const error = await page.locator('#error').textContent().catch(() => '');
  if (error && error.trim()) {
    throw new Error(`the login was refused: ${error.trim().slice(0, 200)}`);
  }
  await page.goto(`${base}/admin/v2/`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1200);
  if (page.url().includes('/admin/login')) {
    throw new Error('the session did not survive the redirect to the console');
  }
}
