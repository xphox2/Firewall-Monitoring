package s3

import (
	"testing"

	"firewall-mon/internal/archive/objstore/objstoretest"
)

// TestConformance runs the archive targets' shared suite against the S3
// client and the B2-strict fake; internal/archive/local runs the same one.
// The in-memory fake is unversioned: a second write replaces the first.
func TestConformance(t *testing.T) {
	objstoretest.Run(t, func(t *testing.T) objstoretest.Harness {
		cl, srv := newFakeClient(t, nil)
		return objstoretest.Harness{
			Store:  cl,
			Prefix: testPrefix,
			Corrupt: func(t *testing.T, rel string) {
				key := testPrefix + "/" + rel
				srv.SetMutateGet(func(k string, body []byte) []byte {
					if k != key || len(body) == 0 {
						return body
					}
					out := append([]byte(nil), body...)
					out[len(out)/2] ^= 0xFF
					return out
				})
			},
		}
	})
}
