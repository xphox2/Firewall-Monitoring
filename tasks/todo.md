# TFTP Config Backup Fix

## Bugs identified
1. **IP:PORT format** sent to FortiGate `execute backup config tftp` — must be bare IPv4, no port (fixed in collector v1.2.63)
2. **TFTP server race condition** — single UDP socket shared between main `serve()` loop and per-transfer goroutines (fixed in collector v1.2.63)
3. **Single global outbound IP from `8.8.8.8` dial** — wrong for firewalls behind LAN/VPN/NAT (fixed in collector v1.2.66)
4. **SSH output discarded** — FortiGate's own success/failure messages were thrown away (fixed in collector v1.2.66)

## Tasks
- [x] Fix IP target format in `sendConfigRevisionViaTFTP` (remove `:69` suffix) — v1.2.63
- [x] Rewrite TFTP server to use a fresh ephemeral UDP socket per transfer (proper TFTP TID handling) — v1.2.63
- [x] Add a WRQ unit test that exercises the multi-packet path — v1.2.63
- [x] Determine outbound IP per device (dial dev.IPAddress) — v1.2.66
- [x] Log FortiGate response from `execute backup config tftp` — v1.2.66
- [x] `go build ./...` + `go test ./...` clean on collector
- [x] Bump collector version + CHANGELOG entry
- [x] Commit + push (collector repo only — server side is correct)

## Verify after deploying v1.2.66 to the probe
- Collector logs at next config-backup attempt:
  - `[TFTP] Determined outbound IP for <dev-ip>: <local-ip>` — confirm `<local-ip>` is on the same subnet/route as the firewall
  - `[TFTP] Sending 'execute backup config tftp ...' to <dev-name>`
  - `[TFTP] FortiGate response from <dev-name>:` followed by the actual CLI output
  - `[TFTP] Received WRQ ...`
  - `[TFTP] WRQ <file> complete: N bytes`
  - `[TFTP] SUCCESS - Received and sent config for device X`
- Server logs: `ReceiveConfigRevision: SAVED config for device X`
- If the FortiGate response shows `Send config file to tftp server failed.` then the per-device outbound IP still isn't reachable from that firewall — investigate routing/NAT between collector and firewall.
