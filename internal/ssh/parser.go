package ssh

import (
	"regexp"
	"strconv"
	"strings"

	"firewall-mon/internal/models"
)

var (
	processLineRegex = regexp.MustCompile(`^\s*(\S+)\s+(\d+)\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%\s+(.+)$`)
	interfaceRegex   = regexp.MustCompile(`^\s*(\S+)\s+.*(errors|discards)\s+(\d+)`)
)

func ParseProcessTop(output string) []models.ProcessInfo {
	var processes []models.ProcessInfo
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "NAME") || strings.HasPrefix(line, "Run Time") {
			continue
		}

		matches := processLineRegex.FindStringSubmatch(line)
		if len(matches) == 6 {
			pid, _ := strconv.Atoi(matches[2])
			cpu, _ := strconv.ParseFloat(matches[3], 64)
			mem, _ := strconv.ParseFloat(matches[4], 64)

			processes = append(processes, models.ProcessInfo{
				Name:    matches[1],
				PID:     pid,
				CPU:     cpu,
				Memory:  mem,
				Command: strings.TrimSpace(matches[5]),
			})
		}
	}
	return processes
}

type InterfaceErrorInfo struct {
	Name        string `json:"name"`
	InErrors    uint64 `json:"in_errors"`
	InDiscards  uint64 `json:"in_discards"`
	OutErrors   uint64 `json:"out_errors"`
	OutDiscards uint64 `json:"out_discards"`
}

func ParseInterfaceList(output string) []InterfaceErrorInfo {
	var interfaces []InterfaceErrorInfo
	var currentName string
	var currentErrs InterfaceErrorInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "===") || strings.HasPrefix(line, "Interface ") {
			if currentName != "" {
				interfaces = append(interfaces, currentErrs)
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentName = parts[1]
			} else {
				currentName = ""
			}
			currentErrs = InterfaceErrorInfo{Name: currentName}
			continue
		}

		if currentName == "" {
			continue
		}

		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "rx errors") {
			if fields := strings.Fields(line); len(fields) >= 3 {
				if v, err := strconv.ParseUint(fields[len(fields)-1], 10, 64); err == nil {
					currentErrs.InErrors = v
				}
			}
		}
		if strings.Contains(lowerLine, "rx discards") {
			if fields := strings.Fields(line); len(fields) >= 3 {
				if v, err := strconv.ParseUint(fields[len(fields)-1], 10, 64); err == nil {
					currentErrs.InDiscards = v
				}
			}
		}
		if strings.Contains(lowerLine, "tx errors") {
			if fields := strings.Fields(line); len(fields) >= 3 {
				if v, err := strconv.ParseUint(fields[len(fields)-1], 10, 64); err == nil {
					currentErrs.OutErrors = v
				}
			}
		}
		if strings.Contains(lowerLine, "tx discards") {
			if fields := strings.Fields(line); len(fields) >= 3 {
				if v, err := strconv.ParseUint(fields[len(fields)-1], 10, 64); err == nil {
					currentErrs.OutDiscards = v
				}
			}
		}
	}

	if currentName != "" {
		interfaces = append(interfaces, currentErrs)
	}

	return interfaces
}

type FortiGateCommands struct {
	ShowConfig     string
	ConfigChecksum string
	ProcessTop     string
	SystemStatus   string
	SystemPerf     string
	InterfaceList  string
}

var Commands = FortiGateCommands{
	ShowConfig:     "show",
	ConfigChecksum: "diagnose sys checksum conf",
	ProcessTop:     "diagnose sys top",
	SystemStatus:   "get system status",
	SystemPerf:     "get system performance status",
	InterfaceList:  "diagnose netlink interface list",
}

type FortiGateParser struct{}

func (p *FortiGateParser) ParseConfig(output string) string {
	return strings.TrimSpace(output)
}

func (p *FortiGateParser) ParseConfigChecksum(output string) string {
	output = strings.TrimSpace(output)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, " checksum") || strings.Contains(line, "md5") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "=" && i+1 < len(parts) {
					return strings.TrimSpace(parts[i+1])
				}
			}
		}
	}
	return output
}

func (p *FortiGateParser) ParseSystemStatus(output string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "===") {
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			result[key] = value
		}
	}
	return result
}

func ParseSystemPerformance(output string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "cpu:") {
			if v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, "CPU:")), 64); err == nil {
				result["cpu"] = v
			}
		}
		if strings.HasPrefix(lowerLine, "memory:") {
			if v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, "Memory:")), 64); err == nil {
				result["memory"] = v
			}
		}
		if strings.HasPrefix(lowerLine, "uptime:") {
			result["uptime"] = strings.TrimSpace(strings.TrimPrefix(line, "Uptime:"))
		}
	}
	return result, nil
}
