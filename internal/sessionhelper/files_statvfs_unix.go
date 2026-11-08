//go:build unix && !linux

package sessionhelper

import (
	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

// statVFS reports dir's file system. Frsize is the block size and Namemax
// 255: the fields every Unix statfs carries are the ones used.
func statVFS(dir string) (*sftp.StatVFS, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return nil, err
	}
	bsize := uint64(st.Bsize)
	return &sftp.StatVFS{
		Bsize: bsize, Frsize: bsize, Blocks: st.Blocks, Bfree: st.Bfree, Bavail: uint64(st.Bavail),
		Files: st.Files, Ffree: uint64(st.Ffree), Favail: uint64(st.Ffree), Namemax: 255,
	}, nil
}
