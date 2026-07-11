package queue

import (
	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// History is the append-only job history: an on-disk collections.Archive that
// holds the flattened ClassAd of every job that reached a terminal state
// (removed or completed) and left the live queue. It is the Go analogue of
// HTCondor's history file.
type History struct {
	arc *collections.Archive
}

// openHistory opens (or creates) the history archive rooted at dir. It first
// tries to reopen an existing archive; if none is present it creates one.
func openHistory(dir string) (*History, error) {
	opts := collections.ArchiveOptions{
		Dir:              dir,
		CategoricalAttrs: []string{"Owner", "User"},
		ValueAttrs:       []string{"ClusterId", "ProcId", "JobStatus"},
	}
	arc, err := collections.OpenArchive(opts)
	if err != nil {
		arc, err = collections.CreateArchive(opts)
		if err != nil {
			return nil, err
		}
	}
	return &History{arc: arc}, nil
}

// Append records a job ad in the history. The ad should already be flattened
// (parent attributes materialized) so the record is self-contained.
func (h *History) Append(ad *classad.ClassAd) error {
	return h.arc.Append(ad)
}

// Flush seals the active segment so recently appended records are queryable and
// durable across a reopen.
func (h *History) Flush() error {
	return h.arc.Flush()
}

// Query returns matching history records, newest first.
func (h *History) Query(q *vm.Query) func(func(*classad.ClassAd) bool) {
	return h.arc.Query(q)
}

// Close seals and unmaps the archive.
func (h *History) Close() error {
	if h == nil || h.arc == nil {
		return nil
	}
	return h.arc.Close()
}
