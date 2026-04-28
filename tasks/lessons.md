# Lessons Learned

## Systemic Failure: QA Always Forgotten

**Problem:** I keep forgetting to run QA checks before commits. User has told me many times.

**What QA Must Happen BEFORE Every Push:**
1. `go build ./...` must succeed
2. `go test ./...` must pass (if tests exist)
3. `git status` must show clean working tree
4. If code changed: verify logic is correct
5. If fix: test the specific fix works
6. ALWAYS show QA results to user BEFORE pushing

**Why I forget:** After each correction, I move on without updating CLAUDE.md in a way that sticks. The rules are documented but I'm not following them consistently.

**What I'm doing about it:**
- Made QA steps EXPLICIT in CLAUDE.md section 2 (was vague before)
- Added explicit checklist that I must verbalize before pushing
- No more "looks good, pushed" - I must show actual test output first

**Remember:**
- QA is NOT optional
- "build passes" is NOT enough - check tests too
- "tests pass" is NOT enough - verify logic if code changed
- ALWAYS show user the QA results before claiming done

---

## Issue: Chart/Graph Issues Are Recurring

### Problem
User repeatedly has to ask for fixes to chart sizing, font sizes, and overflow issues. Each time we fix one chart, another is discovered with the same problems.

### Root Cause
When modifying chart code, I don't proactively check ALL chart-related CSS and JavaScript for consistent settings.

### What to Check EVERY TIME When Working on Charts

1. **Font sizes**: Search for `size: 9` in all JS files - 9px is too small, use 11px minimum
2. **Container padding**: `.chart-card` needs adequate padding (20px) and height (340px) to prevent text clipping
3. **Canvas max-height**: Must leave room for axis labels and legends
4. **Aspect ratio**: Doughnut/pie charts should use `maintainAspectRatio: false`
5. **No duplicate DOM elements**: Check HTML files for duplicate chart containers

### Prevention RULE
**When fixing ANY chart issue:**
1. Grep for all font sizes in chart JS files: `grep -n "size: 9" *.js`
2. Check `.chart-card` CSS height/padding in admin-shared.css
3. Check canvas max-height in admin-shared.css
4. Verify `maintainAspectRatio` is correctly set for doughnut charts
5. Verify dropdown selectors have `chart-range-select` class for proper styling

### Files to Check
- `cmd/api/static/js/admin-device-detail.js` - device charts
- `cmd/api/static/js/admin-connection-detail.js` - connection charts  
- `cmd/api/static/js/admin-main.js` - dashboard charts
- `cmd/api/static/js/diagram-panels.js` - diagram charts
- `cmd/api/static/css/admin-shared.css` - chart container styling

---

## Issue: ConfigText Length Validation

### Problem
SSH config collection may receive incomplete configs. The probe sends a `Length` metadata field that should match `len(ConfigText)`.

### What To Check
1. Server logs show `ReceiveConfigRevision: saved config for device X (len=Y)`
2. If `WARNING: Length mismatch` appears, the probe is sending wrong metadata
3. Check actual config in UI vs what device shows via SSH

### Lesson
- Always validate that metadata Length matches actual content length
- Log both reported and actual lengths for debugging
- Probe-side issues (Firewall-Collector repo) may cause incomplete SSH config collection

## Issue: Force Push Caused Divergent Branch

### Problem
Force pushed after amending commit to fix go.mod. This rewrote remote history and caused team members' local branches to diverge from remote.

### Root Cause
1. I used `git push --force` to update a commit after fixing go.mod
2. Force push overwrites remote history, invalidating anyone who had pulled the old history
3. Team members' local machines had the old commit that was replaced

### What Should Have Happened
1. Instead of amending the commit, create a NEW commit with the go.mod fix:
   ```bash
   git add go.mod go.sum
   git commit -m "fix: resolve go.mod dependency issue"
   git push
   ```
2. Or NEVER force push to shared branches (master/main)

### Lesson
- **NEVER force push to shared/shared branches** (master, main, develop)
- Force push should only be used on private feature branches
- If you need to fix a commit, create a new commit instead of amending
- Always `git fetch` before `git push` to check if remote history changed

### Prevention
- Add git alias or hook to warn when force pushing to master
- Communicate with team before any history-rewriting operation
- Use `git push --force-with-lease` instead of `--force` (still bad but safer)

---

## Issue: IRC Server Save Fails - Missing Database Columns

### Problem
"Failed to save server: SQL logic error: no such column: nickserv_identify"

### Root Causes

1. **GORM AutoMigrate doesn't add columns to existing tables in SQLite**
   - AutoMigrate creates new tables but doesn't reliably add new columns to existing tables
   - **Lesson**: Use GORM Migrator (HasColumn + AddColumn) for schema changes on existing tables

2. **Raw SQL approach failed**
   - SQLite doesn't support "ADD COLUMN IF NOT EXISTS" syntax
   - My early raw SQL attempts failed because they weren't checking column existence properly
   - **Lesson**: Always use GORM's Migrator for database schema changes, not raw SQL

3. **Handler workarounds were wrong**
   - Initially tried skipping fields in the handler to avoid the error
   - This broke functionality (fields not saved)
   - **Lesson**: Fix the root cause (migration) not symptoms

### Fix Applied

Used GORM Migrator to add missing columns after AutoMigrate:
```go
m := d.db.Migrator()
if !m.HasColumn(&models.IRCServer{}, "nickserv_identify") {
    m.AddColumn(&models.IRCServer{}, "nickserv_identify")
}
```

### Prevention
- Always use GORM Migrator for column additions on existing tables
- Test migrations on an existing database, not just fresh ones
- Don't work around database issues in handlers - fix the migration

---

## Issue: IRC TLS Connection Fails

### Problem
"tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config"

### Root Cause
When UseTLS is true, the go-ircevent library requires ServerName to be set in TLSConfig.

### Fix
```go
conn.UseTLS = server.UseTLS
if server.UseTLS && server.ServerHost != "" {
    conn.TLSConfig = &tls.Config{
        ServerName: server.ServerHost,
    }
}
```

### Lesson
- Third-party library TLS requirements vary - always check what fields are needed

---

## Issue: CSRF Token Missing on IRC Page

### Problem
"CSRF token missing" error on IRC page.

### Root Cause
The JavaScript called getCsrfToken() immediately without waiting for the async fetch to complete.

### Fix
Added await before getting token:
```js
await AdminCommon.fetchCsrfToken();
const csrfToken = AdminCommon.getCsrfToken();
```

### Lesson
- Always await async token fetches before using them
- Check how AdminCommon loads in other working pages

---

## Issue: Blank Admin Pages (Sites, Pending Approvals)

### Problem
New admin pages (sites.html, probe-pending.html) showed completely blank white screen with no errors visible.

### Root Causes Found

1. **Duplicate Route Handlers**
   - In `cmd/api/main.go`, there were 3 identical routes for `/probe-pending` 
   - Only the first route would ever execute - the others were dead code
   - **Lesson**: Always check for duplicate route definitions when routes don't work

2. **Duplicate JavaScript Code**
   - The `window.onerror` handler was defined TWICE in each HTML file
   - Second definition overwrote the first
   - This caused silent JavaScript failures
   - **Lesson**: Always verify no duplicate function/variable definitions when debugging

3. **JavaScript Compatibility Issues**
   - Used arrow functions (`() => {}`) and `let` declarations
   - Used complex Promise chaining with `.catch()` syntax
   - No immediate feedback when script failed
   - **Lesson**: When debugging blank pages, start with minimal HTML to verify page loads, then add complexity incrementally. Use IIFE pattern and console.log at every step.

### Fixes Applied

1. Removed duplicate route handlers from main.go
2. Rewrote pages with IIFE pattern using traditional `function` keyword
3. Added console.log statements at every step
4. Wrapped code in `(function() { ... })();` to avoid global scope issues

### Prevention

- When creating new admin pages, verify the route is registered ONCE in main.go
- Always run a syntax check on JavaScript before deploying
- Test pages incrementally - start with minimal HTML, add JS one piece at a time
- Use browser console (F12) to check for JavaScript errors immediately
- Don't use arrow functions if targeting broader compatibility without transpilation

---

## Issue: IRC !status Output Misaligned in IRC Clients

### Problem
Box-drawing status output looked correct in tests but was misaligned when rendered in actual IRC clients.

### Root Causes Found

1. **`len()` counts bytes, not visible characters**
   - Unicode chars like `●` (U+25CF) are 3 bytes but 1 visible char
   - Using `len()` for padding calculation caused 2-char errors per Unicode symbol
   - **Fix**: Use `utf8.RuneCountInString()` for visible width
   - **Lesson**: ALWAYS use rune count, never byte length, for visible width calculations

2. **`\x0F` (reset all) kills ALL formatting mid-line**
   - Original code wrapped every border char in `grey()` which applied color+reset (`\x03XX...\x0F`)
   - Each `\x0F` reset killed any monospace toggle, bold, etc.
   - The `\x11` monospace set at line start was killed by the first `grey()` call
   - **Lesson**: Minimize `\x0F` usage. Use `\x03XX` (set color) to change colors inline without reset.

3. **IRC background color persists when only foreground is set**
   - Per spec: "If only the foreground color is set, the background color stays the same"
   - After bars set bg=black via `\x03XX,01`, using `\x03XX` (fg-only) does NOT clear the black bg
   - **Fix**: Use `\x0F` (reset all) specifically after bars to clear background, then re-set foreground
   - **Lesson**: After any `\x03XX,YY` bg color, you MUST use `\x0F` or `\x03` (bare) to clear bg

4. **`\x11` monospace is unreliable**
   - Only supported by IRCCloud, TheLounge, Textual — NOT mIRC, HexChat, irssi, WeeChat
   - Gets killed by `\x0F` anyway
   - Most IRC clients use monospace fonts by default
   - **Lesson**: Don't rely on `\x11`. Most clients are already monospace.

### Correct IRC Color Pattern
```go
// Set color without reset (no \x0F):
func setC(c string) string { return "\x03" + c }
// Set fg+bg:
func setCBg(fg, bg string) string { return "\x03" + fg + "," + bg }
// Always use 2-digit color codes (00-14) to prevent digit-parsing ambiguity
// Only use \x0F at end of each line, or after bars to clear background
// After bar \x0F, re-apply setC(cWhite) before continuing text
```

### Prevention
- Research protocol specs BEFORE implementing formatting code
- Test with actual IRC clients, not just string-stripping tests
- Don't change visual appearance when fixing alignment bugs — fix only what's broken
- Don't make multiple unrelated changes in one pass (size + format + characters)

---

## Issue: Modal Popups Too Small / Narrow

### Problem
Edit modals (alert policies, etc.) are too small and cramped when opened directly via URL refresh. Content is squished and hard to read.

### Root Cause
**Changed the base `.modal-content` CSS from `width: 520px` to `width: 1100px`**
- Generic `.modal-content` class had a tiny default width of 520px
- Every new modal needed special overrides to be usable
- User had to ask ~6 times to fix the same problem

### Fix Applied
```css
/* BEFORE (too small) */
.modal-content {
    width: 520px;
    max-width: 92vw;
    max-height: 85vh;
}

/* AFTER (good default) */
.modal-content {
    width: 1000px;
    max-width: 92vw;
    max-height: 85vh;
}
```

### Prevention

**RULE: If you create a new modal, check the base `.modal-content` width FIRST**
- If it's under 1000px, it's wrong - increase the base class
- Don't add overrides - fix the base class
- The base class should handle 95% of use cases

**FOR ALL NEW MODALS:**
1. Check if base `.modal-content` width is at least 1000px
2. If modal needs to be wider than 1000px, add inline style `style="width:XXXXpx"`
3. Use `width:XXXXpx` (not `max-width`) as first property for guaranteed override

---

## Issue: Duplicate CSS for Range Pills / Panel Components

### Problem
Range pill buttons (1h, 24h, 7d, 30d) worked in one place (Fullscreen mode) but not another (regular connections page). The `.range-pill` and `.panel-range-pill` classes were defined inline in `connection-detail.html` but not in `admin-shared.css`.

### Root Cause
**Code duplication across files:**
- `connection-detail.html` had its own `.range-pill` CSS
- `diagram-panels.js` used `.panel-range-pill` with no CSS definition anywhere
- No shared CSS module for common UI components like range selectors

### Fix Applied
Added to `admin-shared.css`:
```css
.range-pill, .panel-range-pill {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 9999px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.15s;
    background: #21262d;
    color: #8b949e;
    border: 1px solid #30363d;
}
.range-pill:hover, .panel-range-pill:hover {
    color: #e6edf3;
    border-color: #8b949e;
}
.range-pill.active, .panel-range-pill.active {
    background: #58a6ff;
    color: #fff;
    border-color: #58a6ff;
}
```

### Prevention

**RULE: All reusable UI components MUST be defined in admin-shared.css**
- Range pills, badges, buttons, form elements — if used in multiple places, it goes in shared CSS
- Never define component CSS inline in HTML or in JavaScript template strings
- When adding a new component class, document where it should be used

**BEFORE adding a new component:**
1. Check admin-shared.css if a similar component exists
2. If creating a new reusable pattern, add to admin-shared.css NOT inline styles
3. Verify all usages of similar patterns reference the same CSS class

---

## Issue: TFTP Config Backup — Single Global Outbound IP Wrong For Multi-Path Hosts

### Problem
After fixing the IP:PORT format and the socket race (v1.2.63), TFTP backups *still* didn't arrive for some devices. The SSH command "succeeded", the log said `waiting for upload...`, but no WRQ ever hit the listener.

### Root Cause
The collector determined a **single global** outbound IP at startup by dialing `8.8.8.8`:
```go
c.tftpOutboundIP = c.determineOutboundIP("8.8.8.8")
```
That returns the local source address the kernel uses to reach the public internet. When firewalls live behind a LAN, site-to-site VPN, or NAT, the IP that's reachable *from the firewall* is a different local interface, and FortiGate's `execute backup config tftp <file> <wan-ip>` had no route from the firewall side. The command exited "successfully" because TFTP is fire-and-forget from FortiOS's perspective once the local "send" call is queued.

### Fix
Determine the outbound IP **per device** by dialing the device's own IP — the kernel's route-aware source-address selection then returns the correct local source for that device's network path:
```go
tftpTarget := c.determineOutboundIP(dev.IPAddress)
```

### Lesson — General Principle
Whenever a remote system needs to be told "send to me at IP X" (TFTP, SCP push, syslog target, SNMP trap dest, webhook callback URL), **never use a single global address**. Determine the source address per-target by dialing the target's own IP. `net.Dial("udp", target+":1")` doesn't send any packets; it just lets the kernel pick the source IP it would use for that route. That's the IP the remote system actually sees us at.

### Bonus Diagnostic Lesson
`execute backup config tftp` prints its own status (`config backup successful` / `Send config file to tftp server failed.`). The original code discarded SSH output. Always **capture and log the remote command's output** when invoking `execute`-style vendor commands — half of the diagnosis is on the device side, not the local side.

---

## Issue: TFTP Config Backup — Single-Socket Race + Wrong Argument Format

### Problem
FortiGate config backup over TFTP (replacing SSH `show full-configuration`) appeared to do nothing — no config revisions were ever saved. Lots of iteration on outbound IP detection (v1.2.59–v1.2.62 in collector) didn't fix it because the bugs were elsewhere.

### Two independent bugs (both fatal)

1. **`execute backup config tftp` requires a bare IPv4, not `IP:PORT`**
   The collector built `tftpTarget := c.tftpOutboundIP + ":69"` and passed `192.168.x.x:69` as the server argument. FortiOS treats that as an unresolvable hostname; the SSH command "succeeds" silently and no WRQ is ever sent. **Pass only the IP — TFTP defaults to port 69 anyway.**

2. **TFTP server must use a fresh ephemeral UDP port per transfer (RFC 1350 server TID)**
   The custom server bound a single socket on port 69 and read RRQ/WRQ AND per-transfer DATA on it. The main `serve()` loop and the per-WRQ goroutine both called `ReadFromUDP` on the same socket — incoming DATA packets were distributed by the kernel between them. When the listen loop won the race, it saw opcode 3 (DATA), hit the `default` case, and replied ERROR ("Not implemented"), killing the transfer.

### What to check next time TFTP is involved
- For each WRQ, the server MUST allocate a new `net.ListenUDP(":0")` socket and send ACK 0 from it. All subsequent DATA/ACK for that transfer flow on the new socket. Port 69 only sees the initial RRQ/WRQ.
- TFTP unit tests using `net.DialUDP` are broken-by-design once the server uses ephemeral TIDs — the kernel filters out the server's reply because it comes from an unexpected port. Use `net.ListenUDP` for the test client and `WriteToUDP(serverTID)` for subsequent packets.
- A WRQ test must span >1 block (>512 bytes payload) to catch the race — a single-block transfer can succeed by luck.
- Vendor CLI argument formats are strict. `execute backup config tftp <file> <ip>` — never IP:PORT, never IP:port:other.

### Prevention
- When wrapping vendor CLI commands, write a tiny ssh-test fixture that runs the exact command against a real device early, before building any plumbing around it.
- Custom UDP protocol servers: write a goroutine-style integration test (real client speaking the wire format to real server) before shipping. Race conditions in the dispatch loop are invisible to handler-level unit tests.

---

## CRITICAL: This project has TWO separate repositories

### The Two Repos
1. **Firewall-Mon** (this repo) - Central server that receives data from collectors, runs on stats.technicallabs.org
2. **Firewall-Collector** (separate repo) - Remote collector that SSHes into firewalls and sends data to this server

### Why This Matters
- When user mentions "the collector", "SSH into firewall", or testing SSH commands → work is in the **Collector repo**
- This server repo only receives and stores data that collectors send to it
- Hardware sensors, interface stats, VPN status, etc. are collected by the **Collector** via SSH, then sent here via relay protocol

### What to Do
1. When user asks about SSH-based collection → check the **Collector repo** (E:\Golang\OpenCode\Firewall-Collector)
2. When user mentions something isn't working in "the collector" → look in the Collector repo
3. This server repo handles: API endpoints, database storage, web UI, receiving data from collectors

### Collector Repo Location
`E:\Golang\OpenCode\Firewall-Collector`

### Collector Binary Names
- **collector.exe** - Main collector binary (resides on remote probe machines)
- **ssh-test.exe** - SSH testing utility
