package factory

import (
	"path/filepath"
	"strconv"
)

// SpooledDigestPath returns $(SPOOL)/<cluster%10000>/condor_submit.<cluster>.digest,
// matching GetSpooledSubmitDigestPath (src/condor_utils/spooled_job_files.cpp).
func SpooledDigestPath(spoolDir string, cluster int) string {
	return filepath.Join(spoolDir, strconv.Itoa(cluster%10000),
		"condor_submit."+strconv.Itoa(cluster)+".digest")
}

// SpooledItemsPath returns $(SPOOL)/<cluster%10000>/condor_submit.<cluster>.items,
// matching GetSpooledMaterializeDataPath (spooled_job_files.cpp).
func SpooledItemsPath(spoolDir string, cluster int) string {
	return filepath.Join(spoolDir, strconv.Itoa(cluster%10000),
		"condor_submit."+strconv.Itoa(cluster)+".items")
}
