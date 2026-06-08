// Package response holds the HTTP transport envelope returned by the API
// handlers (AUDIT-073). These types and constructors used to live in
// internal/models alongside the GORM persistence structs, which mixed two
// unrelated concerns — database rows vs. the JSON wire shape — in one package.
// Moving them here keeps internal/models a pure data-layer package and gives
// the transport contract an obvious home next to the handlers that emit it.
//
// The JSON shape is unchanged from the previous models-package version, so this
// is a pure refactor with no effect on any client.
package response

// APIResponse is the standard JSON envelope every handler returns: a success
// flag plus exactly one of Data / Error / Message.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// Success wraps a payload as a successful response.
func Success(data interface{}) APIResponse {
	return APIResponse{
		Success: true,
		Data:    data,
	}
}

// Error wraps an error message as a failed response.
func Error(err string) APIResponse {
	return APIResponse{
		Success: false,
		Error:   err,
	}
}

// Message wraps a human-readable note as a successful response with no payload.
func Message(msg string) APIResponse {
	return APIResponse{
		Success: true,
		Message: msg,
	}
}
