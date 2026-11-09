//go:build unix

package audit

import (
	"os"
	"syscall"
)

// canLock: appends lock the file, so several processes can share a log.
const canLock = true

// lockFile takes an exclusive flock on f, waiting for other holders.
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
