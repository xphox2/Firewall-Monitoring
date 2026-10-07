// Package target opens the archive's target named by ARCHIVE_TARGET: the
// S3-compatible bucket (internal/archive/s3) or a local directory
// (internal/archive/local). Every caller that reads or writes the archive —
// the worker, the seal, the restore, --verify-month, the admin form's
// preflight — opens it here.
package target

import (
	"fmt"

	"firewall-mon/internal/archive/local"
	"firewall-mon/internal/archive/objstore"
	"firewall-mon/internal/archive/s3"
	"firewall-mon/internal/config"
)

// Open builds the target of cfg (ValidateTarget). opts apply to an S3
// target only (tests: the fake's TLS root). It makes no network call and
// touches no file.
func Open(cfg config.ArchiveConfig, opts ...s3.Option) (objstore.Store, error) {
	switch cfg.TargetName() {
	case config.ArchiveTargetS3:
		return s3.New(cfg, opts...)
	case config.ArchiveTargetLocal:
		return local.New(cfg)
	}
	return nil, fmt.Errorf("ARCHIVE_TARGET must be s3 or local, got %q", cfg.Target)
}
