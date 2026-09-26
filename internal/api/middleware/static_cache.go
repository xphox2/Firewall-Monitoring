package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// StaticCache lets browsers keep /static assets between page loads without
// ever running stale code after a deploy.
//
// SecureHeaders marks every response `no-store` — right for authenticated
// HTML and API responses, and the reason it is global — but it also covered
// /static (admin.html alone references 34 assets), and the embedded filesystem
// has no modification times, so there was no Last-Modified or ETag either.
// Every admin page load re-downloaded all of them.
//
// For /static only, this replaces that with `Cache-Control: no-cache` plus a
// strong ETag from the file's content. The browser still asks on every load —
// so a deploy is picked up by a normal reload exactly as before, including the
// Cytoscape bundles that are injected from JS without version strings — but an
// unchanged file is answered 304 with no body. net/http's file server honours
// an ETag already set on the response when it evaluates If-None-Match.
//
// fsys is the filesystem being served. The hash is cached per file and
// recomputed when its size or modification time changes, so the embedded
// files are hashed once and the on-disk tree used for hot fixes stays correct
// when a file is edited. Only a regular file gets the headers; a missing path
// or a directory falls through untouched.
func StaticCache(fsys fs.FS) gin.HandlerFunc {
	type entry struct {
		size int64
		mod  time.Time
		etag string
	}
	var mu sync.Mutex
	cache := make(map[string]entry)

	return func(c *gin.Context) {
		name := strings.TrimPrefix(path.Clean("/"+c.Param("filepath")), "/")
		if name == "" || !fs.ValidPath(name) {
			c.Next()
			return
		}
		fi, err := fs.Stat(fsys, name)
		if err != nil || !fi.Mode().IsRegular() {
			c.Next()
			return
		}

		mu.Lock()
		e, ok := cache[name]
		mu.Unlock()
		if !ok || e.size != fi.Size() || !e.mod.Equal(fi.ModTime()) {
			body, err := fs.ReadFile(fsys, name)
			if err != nil {
				c.Next()
				return
			}
			sum := sha256.Sum256(body)
			// Quoted: net/http ignores an unquoted ETag, and 304 never fires.
			e = entry{size: fi.Size(), mod: fi.ModTime(), etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
			mu.Lock()
			cache[name] = e
			mu.Unlock()
		}

		h := c.Writer.Header()
		h.Set("ETag", e.etag)
		h.Set("Cache-Control", "no-cache")
		h.Del("Pragma")
		c.Next()
	}
}
