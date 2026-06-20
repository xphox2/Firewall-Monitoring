package configdiff

import (
	"regexp"
	"strings"
)

// FortiAuditEvent is the attribution extracted from a FortiGate config-change
// event log message — who changed the config, from where, and how. FortiOS emits
// these as space-separated key=value records (event log, subtype "system",
// logdesc "Object attribute configured" / "Attribute configured", carrying
// cfgpath/cfgobj/cfgattr) without requiring TACACS+ accounting.
type FortiAuditEvent struct {
	IsConfigChange bool   // the message is a config-change audit event
	User           string // admin username (user=)
	Source         string // source IP (srcip=, or the addr inside ui=)
	Method         string // GUI | CLI(ssh) | jsconsole | API | ...
	CfgPath        string // cfgpath= (which config section changed)
}

var (
	// FortiOS kv pairs: key=value or key="quoted value".
	fortiKVRegex = regexp.MustCompile(`(\w[\w-]*)=("(?:[^"\\]|\\.)*"|\S*)`)
	// ui=GUI(10.0.0.5) / ui=ssh(10.0.0.5) / ui=jsconsole / ui=CLI ...
	fortiUIRegex = regexp.MustCompile(`^([A-Za-z_]+)(?:\(([^)]*)\))?`)
)

// ParseFortiAuditEvent extracts change attribution from a single FortiGate log
// line. It reports IsConfigChange=false for lines that are not config-change
// audit events (traffic logs, IPS events, etc.) so callers can ignore them.
func ParseFortiAuditEvent(msg string) FortiAuditEvent {
	kv := map[string]string{}
	for _, m := range fortiKVRegex.FindAllStringSubmatch(msg, -1) {
		kv[strings.ToLower(m[1])] = strings.Trim(m[2], `"`)
	}

	ev := FortiAuditEvent{
		User:    kv["user"],
		CfgPath: kv["cfgpath"],
		Source:  kv["srcip"],
	}

	// A config-change event is identified by cfgpath/cfgattr presence, or by a
	// config-change logdesc/action. This avoids matching traffic or auth logs.
	logdesc := strings.ToLower(kv["logdesc"])
	action := strings.ToLower(kv["action"])
	if _, ok := kv["cfgpath"]; ok {
		ev.IsConfigChange = true
	} else if strings.Contains(logdesc, "attribute configured") ||
		strings.Contains(logdesc, "configuration") ||
		action == "edit" || action == "add" || action == "delete" {
		ev.IsConfigChange = true
	}

	if ui := kv["ui"]; ui != "" {
		if m := fortiUIRegex.FindStringSubmatch(ui); m != nil {
			ev.Method = normalizeFortiMethod(m[1])
			if ev.Source == "" && m[2] != "" {
				ev.Source = m[2]
			}
		}
	}

	return ev
}

// normalizeFortiMethod maps a FortiOS ui= channel to a stable label.
func normalizeFortiMethod(ch string) string {
	switch strings.ToLower(ch) {
	case "gui":
		return "GUI"
	case "ssh", "telnet", "console":
		return "CLI(" + strings.ToLower(ch) + ")"
	case "jsconsole":
		return "jsconsole"
	case "ha", "auto":
		return strings.ToLower(ch)
	default:
		if strings.Contains(strings.ToLower(ch), "api") {
			return "API"
		}
		return ch
	}
}
