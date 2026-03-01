# Lessons Learned

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
