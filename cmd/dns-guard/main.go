package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	guard "github.com/mitetenov/remnawave-dns-guard-backend"
)

func main() {
	health := flag.Bool("healthcheck", false, "check local HTTP health and exit")
	backup := flag.String("backup", "", "write a consistent SQLite backup to a new path and exit")
	restore := flag.String("restore", "", "restore SQLite from a verified backup; stop backend first")
	flag.Parse()
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8000"
	}
	if *health {
		host := addr
		if strings.HasPrefix(host, ":") {
			host = "127.0.0.1" + host
		}
		client := http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
		resp, e := client.Get("http://" + host + "/api/health")
		if e != nil {
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	cfg := guard.ConfigFromEnv()
	if *backup != "" || *restore != "" {
		var e error
		if *backup != "" && *restore != "" {
			log.Fatal("choose one database operation")
		}
		if *backup != "" {
			e = guard.BackupDatabase(cfg.DatabasePath, *backup)
		} else {
			e = guard.RestoreDatabase(cfg.DatabasePath, *restore)
		}
		if e != nil {
			log.Fatal("database operation failed; verify paths, permissions, integrity and that backend is stopped for restore")
		}
		return
	}
	app, e := guard.New(cfg, guard.Options{BackgroundTasks: true})
	if e != nil {
		log.Fatal(e)
	}
	defer app.Close()
	srv := &http.Server{Addr: addr, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stopped)
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- srv.ListenAndServe() }()
	log.Print("DNS Guard backend ready")
	select {
	case e = <-serverErrors:
		if e != nil && e != http.ErrServerClosed {
			log.Print("HTTP server failed")
			_ = app.Close()
			os.Exit(1)
		}
	case <-stopped:
		// Shutdown closes the listener immediately, but active requests still need
		// the store and reconciler until their responses have finished.
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if e = srv.Shutdown(ctx); e != nil {
			log.Print("HTTP shutdown deadline reached")
			_ = srv.Close()
		}
	}
}
