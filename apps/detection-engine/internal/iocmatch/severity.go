package iocmatch

import "strings"

// DeriveSeverity maps IoC confidence to a severity level.
func DeriveSeverity(ioc IoC) string {
	switch {
	case ioc.Confidence >= 90:
		return "critical"
	case ioc.Confidence >= 70:
		return "high"
	case ioc.Confidence >= 50:
		return "medium"
	default:
		return "low"
	}
}

// DeriveMitre maps IoC tags/type to the most relevant MITRE ATT&CK technique.
func DeriveMitre(ioc IoC) (id, name string) {
	lower := strings.Join(ioc.Tags, " ") + " " + strings.ToLower(ioc.Threat)

	switch {
	case containsAny(lower, "c2", "botnet", "command", "control"):
		return "T1071", "Application Layer Protocol"
	case containsAny(lower, "malware_download", "payload", "dropper"):
		return "T1105", "Ingress Tool Transfer"
	case containsAny(lower, "phishing", "credential"):
		return "T1566", "Phishing"
	case containsAny(lower, "exfil", "stealer"):
		return "T1041", "Exfiltration Over C2 Channel"
	case containsAny(lower, "dga", "dynamic"):
		return "T1568", "Dynamic Resolution"
	case containsAny(lower, "miner", "crypto"):
		return "T1496", "Resource Hijacking"
	case containsAny(lower, "scan", "recon"):
		return "T1595", "Active Scanning"
	}

	switch ioc.Type {
	case "domain":
		return "T1071.004", "Application Layer Protocol: DNS"
	case "ip":
		return "T1095", "Non-Application Layer Protocol"
	case "url":
		return "T1071.001", "Application Layer Protocol: Web Protocols"
	case "ja3", "tlsfp":
		return "T1071.001", "Application Layer Protocol: Web Protocols"
	default:
		return "T1071", "Application Layer Protocol"
	}
}

func containsAny(s string, terms ...string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}
