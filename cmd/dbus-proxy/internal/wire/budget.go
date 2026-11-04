package wire

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// Bytes one client may hold in the proxy: its two readers' buffers, a message being handled each way and both
	// write queues, a message's worth each
	maxClientBytes = 6 * MaxMessageSize
	// Bytes all clients together may hold
	maxTotalBytes = 128 << 20
	// File descriptors one client may hold, received and not yet passed on: its readers' pending ones and its queues'
	maxClientFDs = 2 * MaxPendingFDs
)

// What all clients hold together, against limits the proxy can live with
type Budget struct {
	mu               sync.Mutex
	bytes, fds       int64
	MaxBytes, MaxFDs int64
	// Each client's share
	ClientBytes, ClientFDs int64
}

// The file descriptors all clients may hold: half the soft RLIMIT_NOFILE, the rest left for sockets and the runtime
func NewBudget() *Budget {
	var rl unix.Rlimit
	MaxFDs := int64(1024)
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err == nil && rl.Cur != unix.RLIM_INFINITY {
		MaxFDs = int64(rl.Cur) / 2
	}
	return &Budget{MaxBytes: maxTotalBytes, MaxFDs: MaxFDs, ClientBytes: maxClientBytes, ClientFDs: maxClientFDs}
}

// One client's share of the Budget. A nil Account counts nothing (a reader in a unit test)
type Account struct {
	b                *Budget
	mu               sync.Mutex
	bytes, fds       int64
	MaxBytes, MaxFDs int64
}

func (b *Budget) Account() *Account {
	return &Account{b: b, MaxBytes: b.ClientBytes, MaxFDs: b.ClientFDs}
}

// Takes bytes and file descriptors from the client's share and the whole; refused when either would go over
func (a *Account) take(bytes, fds int) error {
	if a == nil || (bytes == 0 && fds == 0) {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bytes+int64(bytes) > a.MaxBytes || a.fds+int64(fds) > a.MaxFDs {
		return fmt.Errorf("Client over its share: %d bytes and %d file descriptors held", a.bytes, a.fds)
	}
	a.b.mu.Lock()
	defer a.b.mu.Unlock()
	if a.b.bytes+int64(bytes) > a.b.MaxBytes || a.b.fds+int64(fds) > a.b.MaxFDs {
		return fmt.Errorf("Proxy over its Budget: %d bytes and %d file descriptors held", a.b.bytes, a.b.fds)
	}
	a.bytes += int64(bytes)
	a.fds += int64(fds)
	a.b.bytes += int64(bytes)
	a.b.fds += int64(fds)
	return nil
}

func (a *Account) give(bytes, fds int) {
	if a == nil || (bytes == 0 && fds == 0) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.b.mu.Lock()
	defer a.b.mu.Unlock()
	a.bytes -= int64(bytes)
	a.fds -= int64(fds)
	a.b.bytes -= int64(bytes)
	a.b.fds -= int64(fds)
}

// Closes file descriptors the Account holds and gives them back
func (a *Account) closeFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
	a.give(0, len(fds))
}
