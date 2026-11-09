//go:build !unix

package audit

import "os"

// canLock: without flock a log has one writer, as before logs were shared.
const canLock = false

func lockFile(*os.File) error   { return nil }
func unlockFile(*os.File) error { return nil }
