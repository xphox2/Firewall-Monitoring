package auth

// RBAC roles (v0.11 access-control epic, P0-1). Stored on models.Admin.Role
// and carried in the JWT Role claim. Single-tenant three-level ladder — every
// permission check is an at-least comparison, so scopes/roles stay one
// dimension (API-token scopes map onto the same ladder in Phase B).
const (
	// RoleViewer can read everything under /admin but mutate nothing.
	RoleViewer = "viewer"
	// RoleOperator can do day-to-day mutations (devices, alerts, sites,
	// probes lifecycle) but not touch settings, users, tokens, or other
	// credential material.
	RoleOperator = "operator"
	// RoleAdmin can do everything, including user/token management and
	// settings. The pre-RBAC single admin maps here.
	RoleAdmin = "admin"
)

// roleLevels orders the ladder. Unknown/empty roles get level 0 — below
// viewer — so a typo'd role in the DB fails closed rather than granting
// access.
var roleLevels = map[string]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
}

// ValidRole reports whether s is one of the three defined roles.
func ValidRole(s string) bool {
	_, ok := roleLevels[s]
	return ok
}

// RoleLevel returns the ladder position of a role (0 for unknown).
func RoleLevel(role string) int {
	return roleLevels[role]
}

// RoleAtLeast reports whether `have` grants at least the rights of `want`.
// Unknown `have` is always false (fail closed); unknown `want` is treated as
// requiring more than any role grants.
func RoleAtLeast(have, want string) bool {
	wl, ok := roleLevels[want]
	if !ok {
		return false
	}
	return roleLevels[have] >= wl
}
