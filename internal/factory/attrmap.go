package factory

// attrKind selects how a digest value maps onto a ClassAd attribute.
type attrKind int

const (
	kindString attrKind = iota // store as a ClassAd string literal
	kindExpr                   // parse as a ClassAd expression (numbers, bools, refs)
	kindArgs                   // arguments: Args (V1) or Arguments (V2)
	kindEnv                    // environment: Env (V1) or Environment (V2)
)

type attrSpec struct {
	attr string
	kind attrKind
}

// attrMap maps the submit-command keys that realistically appear in a pruned
// factory digest (i.e. those whose value varies per proc) to their ClassAd
// attribute + value kind. Non-varying commands are on the cluster ad and never
// reach here; keys absent from this map are skipped by applyAssign.
//
// The submit-command -> attribute names mirror HTCondor's submit_utils.cpp
// (SubmitHash::make_job_ad). This is a focused subset, not the full submit
// grammar; commands with multi-attribute side effects (should_transfer_files,
// etc.) are non-prunable and stay on the cluster ad.
var attrMap = map[string]attrSpec{
	"executable":             {"Cmd", kindString},
	"arguments":              {"", kindArgs},
	"environment":            {"", kindEnv},
	"output":                 {"Out", kindString},
	"error":                  {"Err", kindString},
	"input":                  {"In", kindString},
	"log":                    {"UserLog", kindString},
	"initialdir":             {"Iwd", kindString},
	"initial_dir":            {"Iwd", kindString},
	"iwd":                    {"Iwd", kindString},
	"transfer_input_files":   {"TransferInput", kindString},
	"transfer_output_files":  {"TransferOutput", kindString},
	"transfer_output_remaps": {"TransferOutputRemaps", kindString},
	"request_cpus":           {"RequestCpus", kindExpr},
	"request_memory":         {"RequestMemory", kindExpr},
	"request_disk":           {"RequestDisk", kindExpr},
	"request_gpus":           {"RequestGpus", kindExpr},
	"priority":               {"JobPrio", kindExpr},
	"job_lease_duration":     {"JobLeaseDuration", kindExpr},
	"batch_name":             {"JobBatchName", kindString},
}
