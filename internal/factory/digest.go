// Package factory implements HTCondor late materialization (job factories): a
// compact submit "digest" plus an itemdata table are stored on the cluster ad,
// and proc ads are materialized lazily from them, one row at a time, bounded by
// max_idle / max_materialize.
//
// This file is the pure, testable materializer (roadmap #3, phase 1): it turns a
// (digest text, one itemdata row, cluster id, proc id) tuple into the proc ad's
// per-proc override attributes. The full proc ad is that override chained over
// the cluster ad (the queue's parent chaining supplies every common attribute).
//
// Digest format is HTCondor's, produced by condor_submit's SubmitHash::make_digest
// + append_queue_statement (src/condor_utils/submit_utils.cpp): submit-command
// "key=value" lines (with "key@=end ... @end" heredocs for multi-line values),
// pruned to only the keys whose value still references a per-proc $() macro
// (Process/ProcId/Step/Row/Item/Node or a foreach variable) plus a few
// non-prunable FACTORY.* directives, terminated by a trailing
//
//	Queue [N] [v1,v2,...] [from [slice] <itemsfile>]
//
// statement. Everything else (Cmd, Iwd, RequestCpus, Requirements, JobUniverse,
// Owner, ...) is on the cluster ad, sent by condor_submit before SetJobFactory.
//
// The macro expansion reuses github.com/bbockelm/golang-htcondor/config (the same
// submit/config macro engine condor_submit-in-Go uses): the digest assignments
// are loaded as config values and $(...) is expanded against per-row live
// variables set with HTCondor's exact foreach semantics (verified against stock
// condor_submit -dry-run). The submit-command -> ClassAd-attribute mapping (a
// small, focused table for the keys that actually appear in a pruned digest) is
// new code here; see attrMap.
package factory

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
)

// assign is one digest assignment line (raw, unexpanded value).
type assign struct {
	key   string // submit command / directive key, e.g. "arguments", "FACTORY.Iwd", "+Foo"
	value string // raw value, $() unexpanded
	expr  bool   // true for +Attr / MY.Attr (a ClassAd expression, not a string command)
}

// Digest is a parsed factory submit digest.
type Digest struct {
	assigns   []assign
	queueNum  int      // inner repeat count N of "Queue N ..." (>=1)
	varNames  []string // foreach variable names (empty for "queue N" / unnamed foreach)
	itemsFile string   // itemdata filename from the "from" clause (may be empty)
	slice     string   // slice spec, e.g. "[0:10]" (unsupported for now; recorded)

	cfg *config.Config // reusable macro engine holding the assignments
}

// ItemCount, when a digest has itemdata, is the number of rows; here it is
// derived by the caller from the stored .items file. QueueNum is the inner count.
func (d *Digest) QueueNum() int      { return d.queueNum }
func (d *Digest) VarNames() []string { return d.varNames }
func (d *Digest) ItemsFile() string  { return d.itemsFile }

// ParseDigest parses digest text into a Digest. The trailing Queue statement is
// split off and parsed by hand (its "from <path>" filename contains characters
// the config grammar rejects); the remaining assignment body is parsed with the
// shared config parser so heredocs, dotted keys, +Attr expressions and nested
// $() all behave exactly as in a submit file.
func ParseDigest(text string) (*Digest, error) {
	body, queueLine := splitQueueStatement(text)
	d := &Digest{queueNum: 1}
	if queueLine != "" {
		if err := d.parseQueueLine(queueLine); err != nil {
			return nil, err
		}
	}

	stmts, err := config.Parse(config.NewLexer(strings.NewReader(body)))
	if err != nil {
		return nil, fmt.Errorf("parsing digest body: %w", err)
	}
	cfg := config.NewEmpty()
	for _, s := range stmts {
		a, ok := s.(*config.Assignment)
		if !ok {
			continue // ignore any stray non-assignment (there should be none)
		}
		d.assigns = append(d.assigns, assign{key: a.Name, value: a.Value, expr: a.ClassAdExpr})
		cfg.Set(a.Name, a.Value)
	}
	d.cfg = cfg
	return d, nil
}

// splitQueueStatement returns the digest body (assignments) and the trailing
// Queue statement line. append_queue_statement always appends the Queue line as
// the final non-empty line, so the last line starting (case-insensitively) with
// "queue" is it. Returns queueLine="" if none is found.
func splitQueueStatement(text string) (body, queueLine string) {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		t := strings.TrimSpace(lines[i])
		if t == "" {
			continue
		}
		if len(t) >= 5 && strings.EqualFold(t[:5], "queue") && (len(t) == 5 || t[5] == ' ' || t[5] == '\t') {
			queueLine = t
			body = strings.Join(lines[:i], "\n")
			return body, queueLine
		}
		// The last non-empty line is not a Queue statement: no foreach.
		return text, ""
	}
	return text, ""
}

// parseQueueLine parses "Queue [N] [v1,v2 ...] [from [slice] <itemsfile>]".
func (d *Digest) parseQueueLine(line string) error {
	rest := strings.TrimSpace(line[5:]) // drop "Queue"
	// Optional leading integer count.
	if rest != "" {
		first := rest
		if sp := strings.IndexAny(rest, " \t"); sp >= 0 {
			first = rest[:sp]
		}
		if n, err := strconv.Atoi(first); err == nil {
			d.queueNum = n
			rest = strings.TrimSpace(rest[len(first):])
		}
	}
	if d.queueNum < 1 {
		d.queueNum = 1
	}
	// Split off the "from ..." clause.
	varsPart := rest
	if idx := indexWord(rest, "from"); idx >= 0 {
		varsPart = strings.TrimSpace(rest[:idx])
		fromPart := strings.TrimSpace(rest[idx+4:])
		// Optional slice like [0:10] before the filename.
		if strings.HasPrefix(fromPart, "[") {
			if end := strings.IndexByte(fromPart, ']'); end >= 0 {
				d.slice = fromPart[:end+1]
				fromPart = strings.TrimSpace(fromPart[end+1:])
			}
		}
		d.itemsFile = fromPart
	} else if idx := indexWord(rest, "in"); idx >= 0 {
		// "queue vars in (items)" — inline items are not carried in the wire
		// digest (they become an itemsfile), but handle the vars gracefully.
		varsPart = strings.TrimSpace(rest[:idx])
	} else if idx := indexWord(rest, "matching"); idx >= 0 {
		varsPart = strings.TrimSpace(rest[:idx])
	}
	// Variable names: comma and/or whitespace separated.
	for _, v := range strings.FieldsFunc(varsPart, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		if v != "" {
			d.varNames = append(d.varNames, v)
		}
	}
	return nil
}

// indexWord returns the byte index of a whole-word occurrence of w in s
// (surrounded by whitespace or string ends), or -1.
func indexWord(s, w string) int {
	from := 0
	for {
		i := strings.Index(s[from:], w)
		if i < 0 {
			return -1
		}
		i += from
		leftOK := i == 0 || s[i-1] == ' ' || s[i-1] == '\t'
		rightIdx := i + len(w)
		rightOK := rightIdx >= len(s) || s[rightIdx] == ' ' || s[rightIdx] == '\t'
		if leftOK && rightOK {
			return i
		}
		from = i + len(w)
	}
}
