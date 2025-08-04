//go:build windows

package ipc

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

type Custom struct {
	R uint64 `json:"r"`
	W uint64 `json:"w"`
}

func (c *Custom) isValid() error {
	if c.R == 0 || c.W == 0 {
		return errors.New("invalid pipe handlers")
	}
	return nil
}

func FakeTestCustom(fd int) Custom {
	return Custom{R: uint64(fd), W: uint64(fd + 1)}
}

type FdWrapper struct {
	r syscall.Handle
	w syscall.Handle
}

func (p *FdWrapper) Close() error {
	return errors.Join(syscall.CloseHandle(p.w), syscall.CloseHandle(p.r))
}

func (p *FdWrapper) ToCustomCfg() Custom {
	return Custom{
		R: uint64(p.r),
		W: uint64(p.w),
	}
}

func NewConnectionPair(cmd *exec.Cmd) (io.ReadWriteCloser, *FdWrapper, error) {
	sa := &syscall.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		InheritHandle: 1,
	}
	var p2cR, p2cW syscall.Handle
	if err := syscall.CreatePipe(&p2cR, &p2cW, sa, 0); err != nil {
		return nil, nil, err
	}
	var c2pR, c2pW syscall.Handle
	if err := syscall.CreatePipe(&c2pR, &c2pW, sa, 0); err != nil {
		return nil, nil, err
	}

	closeAll := func() error {
		return errors.Join(
			syscall.CloseHandle(p2cW),
			syscall.CloseHandle(p2cR),
			syscall.CloseHandle(c2pW),
			syscall.CloseHandle(c2pR),
		)
	}

	// The handlers that remain in the parent process don't need to be inherited -> disable
	if err := syscall.SetHandleInformation(p2cW, syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, nil, errors.Join(err, closeAll())
	}
	if err := syscall.SetHandleInformation(c2pR, syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, nil, errors.Join(err, closeAll())
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		AdditionalInheritedHandles: []syscall.Handle{p2cR, c2pW},
		CreationFlags:              syscall.CREATE_NEW_PROCESS_GROUP, // required so we can send windows.CTRL_BREAK_EVENT
	}
	return &PipeConn{
		R: os.NewFile(uintptr(c2pR), "child-parent"),
		W: os.NewFile(uintptr(p2cW), "parent-child"),
	}, &FdWrapper{r: p2cR, w: c2pW}, nil
}

// FromCustomCfg is the counter part of ToCustomCfg().
// Turns a win pipe handler pair back into an io.ReadWriteCloser
func FromCustomCfg(cfg Custom) (io.ReadWriteCloser, error) {
	return &PipeConn{
		R: os.NewFile(uintptr(cfg.R), "child-parent"),
		W: os.NewFile(uintptr(cfg.W), "parent-child"),
	}, nil
}

var _ io.ReadWriteCloser = &PipeConn{}

// PipeConn turns a pair of uni directional pipe handlers into a bidirectional io.ReadWriteCloser
type PipeConn struct {
	R *os.File
	W *os.File
}

func (p *PipeConn) Read(b []byte) (int, error)  { return p.R.Read(b) }
func (p *PipeConn) Write(b []byte) (int, error) { return p.W.Write(b) }
func (p *PipeConn) Close() error {
	return errors.Join(p.R.Close(), p.W.Close())
}
