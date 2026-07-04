package proxy

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// zstdPool reuses encoders across responses (creating one allocates lookup
// tables). Encoders are Reset onto each new pipe writer.
var zstdPool = sync.Pool{
	New: func() any {
		enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
		return enc
	},
}

// zstdReader streams-compresses orig with zstd via an io.Pipe, so the response
// is never fully buffered in memory.
func zstdReader(orig io.ReadCloser) io.ReadCloser {
	pr, pw := io.Pipe()
	enc := zstdPool.Get().(*zstd.Encoder)
	enc.Reset(pw)
	go func() {
		_, copyErr := io.Copy(enc, orig)
		closeErr := enc.Close()
		zstdPool.Put(enc)
		_ = orig.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		_ = pw.CloseWithError(copyErr)
	}()
	return pr
}

// shouldCompress decides whether to zstd-encode a backend response for a client
// that supports it. It skips already-encoded, non-compressible, tiny, and
// bodyless responses.
func shouldCompress(req *http.Request, resp *http.Response, minSize int) bool {
	if resp.Header.Get("Content-Encoding") != "" {
		return false
	}
	if !acceptsZstd(req.Header.Get("Accept-Encoding")) {
		return false
	}
	if !compressibleType(resp.Header.Get("Content-Type")) {
		return false
	}
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotModified, http.StatusPartialContent:
		return false
	}
	if resp.ContentLength >= 0 && int(resp.ContentLength) < minSize {
		return false
	}
	return true
}

// acceptsZstd reports whether the Accept-Encoding header lists zstd (not q=0).
func acceptsZstd(ae string) bool {
	for _, part := range strings.Split(ae, ",") {
		tok := strings.TrimSpace(part)
		name, params, _ := strings.Cut(tok, ";")
		if strings.EqualFold(strings.TrimSpace(name), "zstd") {
			return !strings.Contains(strings.ReplaceAll(params, " ", ""), "q=0")
		}
	}
	return false
}

// compressibleType returns true for text-like content types worth compressing.
func compressibleType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	// Server-Sent Events are a long-lived stream: compressing them buffers the
	// pipe and delays real-time delivery, so never compress them.
	if ct == "text/event-stream" {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json", "application/javascript", "application/xml",
		"application/xhtml+xml", "application/rss+xml", "application/atom+xml",
		"application/ld+json", "application/manifest+json", "application/wasm",
		"image/svg+xml", "application/x-javascript":
		return true
	}
	return false
}
