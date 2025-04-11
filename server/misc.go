package server

// RespFunc defines a function signature that returns
// bytes for TCP segments.
type RespFunc func() ([]byte, error)
