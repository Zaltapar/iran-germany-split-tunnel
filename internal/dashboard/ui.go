package dashboard

import (
	"embed"
	"io"
	"net/http"
	"strconv"
	"strings"
)

//go:embed static/*
var staticFS embed.FS

// serveUI handles the embedded read-only web UI.
// It serves index.html at "/" and static assets under "/static/".
// No external CDN, no remote fonts, no remote scripts — all assets are
// embedded in the binary.
func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path != "/" && !strings.HasPrefix(path, "/static/") {
		http.NotFound(w, r)
		return
	}

	if path == "/" {
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "UI asset not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
		return
	}

	// Serve static assets (CSS, JS, images) from the embedded FS.
	rel := strings.TrimPrefix(path, "/")
	f, err := staticFS.Open(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	contentType := mimeFromExt(rel)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	stat, err := f.Stat()
	if err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	}
	_, _ = io.Copy(w, f)
}

// MIME types for the embedded assets. No external dependencies.
func mimeFromExt(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		return "application/json"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}
