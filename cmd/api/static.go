// Package main is the entry point for the firewall-mon API binary.
// See cmd/api/main.go for the high-level architecture.
//
// AUDIT-169: the staticFiles embed lives in this file rather than
// in an `internal/` package. The trade-off:
//
//   - **Layering purist view:** an `internal/` package is the
//     canonical home for an embed.FS used by a binary. It keeps
//     `cmd/` purely a "main" and makes the embed reusable from
//     other commands in the future.
//
//   - **Pragmatic view:** staticFiles is consumed only by the
//     gin router in cmd/api/main.go. The embed directive
//     `//go:embed static` resolves paths relative to the source
//     file, so moving it to `internal/` would also require
//     reorganizing the `static/` directory (or copying it),
//     neither of which buys anything today. The audit doc
//     explicitly calls out "Acceptable as-is. Document the
//     choice." — this comment is that documentation.
//
// If a second binary in the project ever needs the same embed
// (e.g. a `cmd/admin-tools/` that ships a CLI version of the
// admin UI), the right move is to lift `static/` and the
// `staticFiles` declaration to `internal/webassets/`. The
// directory layout should follow the second consumer, not the
// first.
package main

import "embed"

//go:embed static
var staticFiles embed.FS
