package main

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"strconv"

	. "github.com/mickael-kerjean/webpty/common"
	"github.com/mickael-kerjean/webpty/common/ssl"
	"github.com/mickael-kerjean/webpty/ctrl"
)

var port int = 13456

func init() {
	if pStr := os.Getenv("PORT"); pStr != "" {
		if pInt, err := strconv.Atoi(pStr); err == nil {
			port = pInt
		}
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", ctrl.Main)
	mux.HandleFunc("/login", ctrl.HandlerLogin)
	mux.HandleFunc("/setup", ctrl.SetupTunnel)
	mux.HandleFunc("/tunnel.js", ctrl.RedirectTunnel)
	mux.HandleFunc("/healthz", ctrl.HealthCheck)
	mux.HandleFunc("/favicon.ico", ctrl.ServeFavicon)

	msg := `
    ██╗    ██╗███████╗██████╗ ██████╗ ████████╗██╗   ██╗
    ██║    ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝╚██╗ ██╔╝
    ██║ █╗ ██║█████╗  ██████╔╝██████╔╝   ██║    ╚████╔╝
    ██║███╗██║██╔══╝  ██╔══██╗██╔═══╝    ██║     ╚██╔╝
    ╚███╔███╔╝███████╗██████╔╝██║        ██║      ██║
     ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝        ╚═╝      ╚═╝

    Web Interface:
`
	for _, url := range GetAddress() {
		msg += fmt.Sprintf("    - https://%s:%d\n", url, port)
	}
	Log.Stdout(msg + "\nLOGS:")
	TLSCert, _, err := ssl.GenerateSelfSigned()
	if err != nil {
		Log.Error("ssl.GenerateSelfSigned %s", err.Error())
		return
	}
	Log.Info("WebPty is ready to go")

	if err := (&http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			Certificates: []tls.Certificate{TLSCert},
		},
		ErrorLog: NewNilLogger(),
	}).ListenAndServeTLS("", ""); err != nil {
		Log.Error("[https]: listen_serve %v", err)
	}
}
