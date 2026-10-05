// Minimal static HTTP server — the trivial payload for the curated sample
// base image. No external dependencies (stdlib only) so the build stays
// hermetic and the binary links fully static with CGO_ENABLED=0.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello from the sisyfix hardened base image")
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	log.Printf("static-hello listening on %s", addr)
	// #nosec G114 — sample server; timeouts are not material to the slice.
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
