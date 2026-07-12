package factory

import (
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/config"
)

// ItemSeparator is the field separator condor_submit uses inside an itemdata row
// when the foreach has multiple variables (ASCII Unit Separator), matching
// AbstractScheddQ::next_rowdata in src/condor_utils/submit_protocol.cpp.
const ItemSeparator = "\x1f"

// RowIndex returns the itemdata row index (0-based) that materializes proc p,
// given the digest's inner repeat count. Procs are contiguous from 0, so
// row = p / N and step = p % N (matching HTCondor's init_vars / next_row).
func (d *Digest) RowIndex(proc int) int { return proc / d.queueNum }

// Step returns the inner step (0..queueNum-1) for proc p.
func (d *Digest) Step(proc int) int { return proc % d.queueNum }

// Materialize expands one proc ad's per-proc OVERRIDE attributes from the digest
// and the itemdata row that feeds it. rawRow is the raw itemdata line for
// d.RowIndex(proc) (empty for a "queue N" factory with no items). The returned
// ad carries ONLY the attributes the digest contributes for this proc; the full
// job ad is this override chained over the cluster ad. ClusterId/ProcId and the
// commit-time identity attributes are added by the queue when it stores the ad.
//
// Live foreach variables are set with HTCondor's exact semantics (verified
// against condor_submit -dry-run):
//   - Process/ProcId/Node = proc
//   - Cluster/ClusterId    = cluster
//   - Step                 = proc % queueNum
//   - Row/ItemIndex        = proc / queueNum
//   - Item                 = the raw row string when there are NO named vars,
//     otherwise unset (expands empty)
//   - each named var       = its split field from the row
//
// The config macro engine is case-sensitive, so each live variable is set under
// both its canonical name and its lowercase form (HTCondor macro names are
// case-insensitive).
func (d *Digest) Materialize(cluster, proc int, rawRow string) (*classad.ClassAd, error) {
	row := d.RowIndex(proc)
	step := d.Step(proc)

	setVar(d.cfg, "Cluster", strconv.Itoa(cluster))
	setVar(d.cfg, "ClusterId", strconv.Itoa(cluster))
	setVar(d.cfg, "Process", strconv.Itoa(proc))
	setVar(d.cfg, "ProcId", strconv.Itoa(proc))
	setVar(d.cfg, "Node", strconv.Itoa(proc))
	setVar(d.cfg, "Step", strconv.Itoa(step))
	setVar(d.cfg, "Row", strconv.Itoa(row))
	setVar(d.cfg, "ItemIndex", strconv.Itoa(row))

	fields := splitRow(rawRow, len(d.varNames))
	if len(d.varNames) == 0 {
		setVar(d.cfg, "Item", rawRow)
	} else {
		// Named foreach: $(Item) is unset (expands to empty), matching stock.
		setVar(d.cfg, "Item", "")
		for i, name := range d.varNames {
			v := ""
			if i < len(fields) {
				v = fields[i]
			}
			setVar(d.cfg, name, v)
		}
	}

	ad := classad.New()
	for _, a := range d.assigns {
		applyAssign(ad, d.cfg, a)
	}
	return ad, nil
}

// setVar sets a live macro under both the given name and its lowercase form so
// digest references in either case resolve (HTCondor macros are case-insensitive
// but the config engine is not).
func setVar(cfg interface{ Set(string, string) }, name, value string) {
	cfg.Set(name, value)
	if l := strings.ToLower(name); l != name {
		cfg.Set(l, value)
	}
}

// splitRow splits an itemdata row into fields. Fields are separated by the ASCII
// Unit Separator when condor_submit packed a multi-var row; otherwise (or for a
// single var) the row is split on whitespace when more than one field is wanted.
func splitRow(row string, nvars int) []string {
	if row == "" {
		return nil
	}
	if strings.Contains(row, ItemSeparator) {
		return strings.Split(row, ItemSeparator)
	}
	if nvars <= 1 {
		return []string{row}
	}
	return strings.Fields(row)
}

// applyAssign expands one digest assignment and sets the mapped attribute(s) on
// the proc override ad. Unknown submit commands are skipped (the digest only
// carries per-proc-varying keys, so this covers the realistic set; see attrMap).
func applyAssign(ad *classad.ClassAd, cfg *config.Config, a assign) {
	key := a.key
	// FACTORY.* directives.
	if strings.HasPrefix(strings.ToUpper(key), "FACTORY.") {
		sub := key[len("FACTORY."):]
		switch strings.ToLower(sub) {
		case "iwd":
			ad.InsertAttrString("Iwd", getExpanded(cfg, key))
		}
		// FACTORY.Requirements=MY.Requirements and any other FACTORY directive is
		// satisfied by the cluster ad via chaining; skip.
		return
	}
	// +Attr / MY.Attr : a raw ClassAd expression attribute.
	if a.expr || strings.HasPrefix(key, "+") || strings.HasPrefix(strings.ToLower(key), "my.") {
		name := strings.TrimPrefix(key, "+")
		name = trimMyPrefix(name)
		setExpr(ad, name, getExpanded(cfg, key))
		return
	}

	m, ok := attrMap[strings.ToLower(key)]
	if !ok {
		return // unknown / non-materializing submit command
	}
	val := getExpanded(cfg, key)
	switch m.kind {
	case kindArgs:
		// V1 (unquoted) -> Args; V2 (quoted) -> Arguments (stock condor_submit).
		if isQuoted(a.value) {
			ad.InsertAttrString("Arguments", unquote(val))
		} else {
			ad.InsertAttrString("Args", val)
		}
	case kindEnv:
		if isQuoted(a.value) {
			ad.InsertAttrString("Environment", unquote(val))
		} else {
			ad.InsertAttrString("Env", val)
		}
	case kindExpr:
		setExpr(ad, m.attr, val)
	default: // kindString
		ad.InsertAttrString(m.attr, val)
	}
}

// getExpanded returns the macro-expanded value for a digest key.
func getExpanded(cfg *config.Config, key string) string {
	v, _ := cfg.Get(key)
	return v
}

// setExpr sets attr to a ClassAd expression parsed from val, falling back to a
// string literal if val does not parse as an expression.
func setExpr(ad *classad.ClassAd, attr, val string) {
	if expr, err := classad.ParseExpr(val); err == nil {
		ad.InsertExpr(attr, expr)
		return
	}
	ad.InsertAttrString(attr, val)
}

func trimMyPrefix(s string) string {
	if len(s) >= 3 && strings.EqualFold(s[:3], "my.") {
		return s[3:]
	}
	return s
}

// isQuoted reports whether a raw submit value is a double-quoted (V2) form.
func isQuoted(raw string) bool {
	raw = strings.TrimSpace(raw)
	return len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"'
}

// unquote strips one layer of surrounding double quotes and unescapes doubled
// quotes, the inverse of HTCondor's V2 quoting for a fully-expanded value.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, `""`, `"`)
}
