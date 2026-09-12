// Package web embeds the verification/approval page templates into the binary.
package web

import "embed"

//go:embed templates/*.html
var Templates embed.FS
