// Command rubysift runs the RubySift desktop companion: a loopback-only
// local server that decrypts Ruby's .pclog telemetry logs in memory and
// serves the analytics dashboard.
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"

	"github.com/0xKnowles/RubySift/internal/server"
)

//go:embed web
var webFS embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "loopback address to listen on")
	flag.Parse()

	assets, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}

	srv := server.New(http.FS(assets))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("rubysift: failed to bind %s: %v", *addr, err)
	}
	log.Printf("RubySift listening on http://%s (loopback only)", ln.Addr())
	log.Fatal(http.Serve(ln, srv.Handler()))
}
