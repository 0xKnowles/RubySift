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
	"os/exec"
	"runtime"

	"github.com/0xKnowles/RubySift/internal/server"
)

//go:embed web
var webFS embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "loopback address to listen on")
	noOpen := flag.Bool("no-open", false, "don't automatically open the dashboard in a browser")
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
	url := "http://" + ln.Addr().String()
	log.Printf("RubySift listening on %s (loopback only) — open that URL in a browser", url)

	if !*noOpen {
		if err := openBrowser(url); err != nil {
			log.Printf("Couldn't auto-open a browser (%v) — open %s yourself", err, url)
		}
	}

	log.Fatal(http.Serve(ln, srv.Handler()))
}

// openBrowser launches the OS default browser at url. RubySift is a background server with no
// window of its own, so without this a user who just double-clicked the binary sees nothing
// happen at all — the server is listening, but nothing tells them to go open a browser.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
