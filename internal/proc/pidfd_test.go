package proc

import (
	"os"
	"os/exec"
	"os/signal"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A running process is alive however often signals interrupt the poll
func TestAliveInterrupted(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	// Handled, so the poll returns EINTR rather than the signal being ignored
	sig := make(chan os.Signal, 1024)
	signal.Notify(sig, unix.SIGUSR1)
	defer signal.Stop(sig)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-sig:
			default:
				unix.Tgkill(os.Getpid(), unix.Gettid(), unix.SIGUSR1)
				unix.Kill(os.Getpid(), unix.SIGUSR1)
			}
		}
	}()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		if !Alive(fd) {
			t.Fatal("A running process reported gone")
		}
	}
	cmd.Process.Kill()
	cmd.Wait()
	if Alive(fd) {
		t.Error("An ended process reported alive")
	}
}
