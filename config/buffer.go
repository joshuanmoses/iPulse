package config

import "bytes"

// Small aliases keep the YAML plumbing in load.go readable without importing bytes
// throughout the package.
type writeBuffer = bytes.Buffer

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
