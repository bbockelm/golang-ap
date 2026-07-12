package factory

import "strings"

// ParseItems splits stored itemdata bytes into rows. condor_submit streams one
// row per line (newline-terminated), fields within a multi-var row joined by the
// ASCII Unit Separator (see next_rowdata). A trailing newline does not produce an
// empty final row; blank lines are dropped (matching the schedd's row counting).
func ParseItems(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	raw := strings.Split(string(data), "\n")
	rows := make([]string, 0, len(raw))
	for _, line := range raw {
		// Rows keep their internal \x1F separators; only strip a trailing \r.
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		rows = append(rows, line)
	}
	return rows
}
