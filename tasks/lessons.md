# Lessons Learned

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
