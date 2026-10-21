package toolchain

#Tools: {
	...
	"github:redpanda-data/connect": "4.112.0"
	"github:caddyserver/caddy":     "2.10.0"
	"github:FiloSottile/mkcert":    "v1.4.4"
	"github:bonisoft3/mecha":       "0.13.0"
	// The services a host launch runs as processes (cluster.cue's `_host`):
	// postgres with ICU from one portable build per platform, and its client
	// tools; PostgREST at the image's version; pgroll at the migrate image's.
	"github:theseus-rs/postgresql-binaries": "18.6.1"
	"github:PostgREST/postgrest":            "v16.4"
	"aqua:xataio/pgroll":                    "0.16.3"
}
