package transport

import "os"

// SocketPathEnv names the environment variable that overrides the daemon endpoint.
//
// It is the ONE knob that points `av`, `avd` and `age-plugin-av` at the same endpoint
// on every platform, which is what makes an isolated instance possible: an ephemeral
// daemon on a private path, side by side with the user's real one. scripts/smoke-sops.sh
// gets that on Unix by pointing $XDG_RUNTIME_DIR at a temp dir, but that lever does not
// exist on Windows — the default there is derived from %LOCALAPPDATA% — so without this
// variable there is no way to run a second instance on Windows at all.
//
// The value is the LOGICAL endpoint path on both platforms. On Unix it is the unix socket
// itself (and so is still subject to the ~104-byte sun_path limit Listen enforces). On
// Windows the named pipe is derived from it by pipeNameFromPath, and its parent dir holds
// the daemon's lockfile and audit log — so two different override paths are two fully
// independent instances there, exactly as on Unix.
const SocketPathEnv = "AV_SOCKET_PATH"

// socketPathOverride returns the endpoint override and whether one was set.
func socketPathOverride() (string, bool) {
	p := os.Getenv(SocketPathEnv)
	return p, p != ""
}
