package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// syncStore copies the sandbox closure into its own store and roots it, when the root doesn't point at it yet. The
// store is the sandbox's to write, so Nix works on it only through claude-desktop-state, confined to stateDir/nix; the
// stream it imports comes from the host's store. progress, when given, hears how far the copy is, 0 to 1
func syncStore(cfg *config, progress func(float64)) error {
	nixDir := filepath.Join(cfg.StateDir, "nix")
	store := filepath.Join(nixDir, "store")
	// nixpak binds the store directory on its own, following a link there on the host. Nothing runs in the sandbox now
	if fi, err := os.Lstat(store); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a link, which only the sandbox could have put there. Remove it", store)
	}
	// The store directory the sync made, by device and inode, kept where the sandbox can't write. The sandbox can rename
	// a directory that is a mountpoint where it runs from a namespace of its own (models/README.md, S12) and put a
	// directory of its own in its place, which a check for a link misses
	idFile := filepath.Join(cfg.StateDir, "nix-store.id")
	if recorded, err := os.ReadFile(idFile); err != nil || strings.TrimSpace(string(recorded)) != devIno(store) {
		// No record (an install from before the launcher kept one), or a store directory the sandbox put in place of
		// the one recorded. Either way nothing in nix/ can be trusted, and nothing in it is the host's: it goes whole
		// and the closure is copied into a fresh one. As root of a userns holding the user's subuids and subgids, so
		// files a container in the sandbox made go too. Outside confine.sh, whose userns maps the user alone; rm doesn't
		// follow links, and the sandbox isn't running
		if _, err := os.Lstat(nixDir); err == nil {
			fmt.Fprintf(os.Stderr, "%s: %s isn't the store directory this launcher recorded, so %s is deleted and the "+
				"closure copied afresh\n", progName(cfg), store, nixDir)
			rm := exec.Command(cfg.Tools.Unshare, "--map-auto", "--map-root-user", "rm", "-rf", nixDir)
			// unshare runs newuidmap and newgidmap from PATH
			rm.Env = append(os.Environ(), "PATH="+os.Getenv("PATH")+":"+cfg.Tools.WrapperDir)
			if out, err := rm.CombinedOutput(); err != nil {
				return fmt.Errorf("Delete %s: %w: %s", nixDir, err, out)
			}
		}
		// The record goes in before the first copy, so a sync that doesn't finish goes on in the same directory next
		// time
		if err := os.MkdirAll(store, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(idFile+".tmp", []byte(devIno(store)+"\n"), 0o644); err != nil {
			return err
		}
		if err := os.Rename(idFile+".tmp", idFile); err != nil {
			return err
		}
	}
	// Dependencies first, as the import needs them
	out, err := exec.Command(cfg.Tools.NixStore, "-qR", cfg.StoreRoots).Output()
	if err != nil {
		return fmt.Errorf("Query the sandbox closure: %w", err)
	}
	closure := strings.Fields(string(out))
	missingCmd := exec.Command(cfg.State, nixDir, "--", "store-missing", cfg.StoreRoots)
	missingCmd.Stdin = strings.NewReader(strings.Join(closure, "\n") + "\n")
	out, err = missingCmd.Output()
	if err != nil {
		return fmt.Errorf("Compare the sandbox's store: %w", err)
	}
	status, rest, _ := strings.Cut(string(out), "\n")
	if status == "current" {
		return nil
	}
	// Only paths of the closure, in its order, whatever the sandbox's store answered
	invalid := map[string]bool{}
	for _, p := range strings.Fields(rest) {
		invalid[p] = true
	}
	var missing []string
	for _, p := range closure {
		if invalid[p] {
			missing = append(missing, p)
		}
	}
	importCmd := exec.Command(cfg.State, nixDir, "--", "store-import", cfg.StoreRoots)
	importCmd.Stderr = os.Stderr
	if len(missing) == 0 {
		importCmd.Args = append(importCmd.Args, "none")
		if err := importCmd.Run(); err != nil {
			return fmt.Errorf("Root the sandbox closure: %w", err)
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s: Copying the sandbox closure to %s\n", progName(cfg), nixDir)
	return export(cfg, missing, importCmd, progress)
}

// export streams missing from the host's store into importCmd, telling progress the share of their NAR size sent
func export(cfg *config, missing []string, importCmd *exec.Cmd, progress func(float64)) error {
	total := narSize(cfg, missing)
	exportCmd := exec.Command(cfg.Tools.NixStore, append([]string{"--export"}, missing...)...)
	exportCmd.Stderr = os.Stderr
	stream, err := exportCmd.StdoutPipe()
	if err != nil {
		return err
	}
	importCmd.Stdin = &counter{r: stream, total: total, progress: progress}
	if err := exportCmd.Start(); err != nil {
		return fmt.Errorf("Export the sandbox closure: %w", err)
	}
	importErr := importCmd.Run()
	// The import may stop reading early; the export then ends on a broken pipe
	stream.Close()
	exportErr := exportCmd.Wait()
	if importErr != nil {
		return fmt.Errorf("Import the sandbox closure: %w", importErr)
	}
	if exportErr != nil {
		return fmt.Errorf("Export the sandbox closure: %w", exportErr)
	}
	return nil
}

// narSize sums the NAR sizes of paths, which the export stream is a little longer than; 0 when unknown
func narSize(cfg *config, paths []string) int64 {
	out, err := exec.Command(cfg.Tools.NixStore, append([]string{"-q", "--size"}, paths...)...).Output()
	if err != nil {
		return 0
	}
	var sum int64
	for _, f := range strings.Fields(string(out)) {
		n, _ := strconv.ParseInt(f, 10, 64)
		sum += n
	}
	return sum
}

// counter tells progress how much of total went through r, below 1 until it ends
type counter struct {
	r        io.Reader
	n, total int64
	last     float64
	progress func(float64)
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.progress != nil && c.total > 0 {
		f := min(float64(c.n)/float64(c.total), 0.99)
		// A percent at a time
		if f-c.last >= 0.01 || errors.Is(err, io.EOF) {
			c.last = f
			c.progress(f)
		}
	}
	return n, err
}

// devIno identifies path by device and inode, as stat -c %d:%i does; empty when it can't be read
func devIno(path string) string {
	var st unix.Stat_t
	if unix.Stat(path, &st) != nil {
		return ""
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%d:%d", st.Dev, st.Ino)
	return b.String()
}
