// Package vendors registers every IPSec provisioning driver via blank imports.
// Import this package (for side effects) from the server and collector to make
// all vendors available in the registry. Adding a vendor = one import line here
// plus its driver package — no core changes.
package vendors

import (
	_ "firewall-mon/internal/ipsec/vendors/fortigate"
	_ "firewall-mon/internal/ipsec/vendors/opnsense"
)
