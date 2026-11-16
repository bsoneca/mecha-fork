// host_peer_process_compose_check.cue — bayt's own renderers (gen_process_compose.cue,
// gen_compose.cue), run end to end against the exact ref doorOwn's hostPeers loop
// emits (cluster.cue, PRONTO_UPSTREAM_<NAME>). host_peer_process_compose_test.ts
// asserts against this. Pinned to the bayt version cue.mod/module.cue names: a bump
// that changes this is a renderer change to re-verify, not a regression in cluster.cue.
package cluster

import (
	bayt "github.com/bonisoft3/bayt/core:bayt"
)

_hostPeerProject: bayt.#project & {
	name:     "p"
	dir:      "p"
	activate: ""
	targets: {
		caddy: {
			entrypoint: {
				do: "caddy run"
				env: {
					// The exact two shapes doorOwn's hostPeers loop emits: a peer
					// that is a bayt target exposing http, and one that is not.
					PRONTO_UPSTREAM_RENDERER: {peer: "renderer", port: "http", host: "127.0.0.1"}
					PRONTO_UPSTREAM_SIDECAR:  "127.0.0.1:4001"
				}
			}
			dockerfile: from: name: "caddy:2"
			compose: {}
		}
		renderer: {
			expose: http: {port: 9100, env: "PORT"}
			entrypoint: do: "renderer"
			dockerfile: from: name: "alpine:3"
			compose: {}
		}
	}
}

#_hostPeerProcessCompose: (bayt.#processComposeGen & {project: _hostPeerProject, depManifests: {}}).file.processes.caddy.environment
#_hostPeerDockerCompose:  (bayt.#dockerComposeGen & {project: _hostPeerProject, depManifests: {}}).compose.files.caddy.services."p-caddy".environment
