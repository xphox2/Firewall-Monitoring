# Lessons Learned

## 2026-03-07: Dual Repository Architecture - VPN Tunnel Fix

### Problem
User reported VPN tunnels not showing correctly on the device detail page. User kept asking to fix "the collector" or "the probe" while I was only fixing the server (Firewall-Mon).

### Root Cause
There are TWO separate GitHub repositories:
1. **Firewall-Mon** - The API server (where I was making changes)
2. **Firewall-Collector** - The probe/collector (where changes were actually needed)

I never asked about or verified the repository architecture. I assumed all code was in one repo.

### What Went Wrong
- Made SNMP fixes to Firewall-Mon
- Probe code is in Firewall-Collector (separate repo)
- User kept saying "probe" and "collector" - I didn't understand these referred to a separate repo
- Made the user repeat themselves multiple times while I kept asking for logs and making wrong assumptions

### Key Takeaway
When user mentions "collector", "probe", or mentions a second system component, ALWAYS verify:
1. Is there a separate repository for the collector/probe?
2. Does the collector have its own code that needs updating?
3. Ask explicitly: "Is there a separate collector repository?"

### Fix Applied
Need to apply same SNMP fixes to Firewall-Collector repo:
- Change `GetVPNStatus()` to `GetAllVPNTunnels()` in collector code
- Sync SNMP OID parsing fixes

### Never Again
- Don't assume single repo architecture
- Ask about collector/probe repos upfront
- Don't keep asking for logs - ask clarifying questions about architecture first
