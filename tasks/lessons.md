# Lessons Learned

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
