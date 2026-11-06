// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package flock

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxBytes = ^uint32(0) // lock the whole file
)

func openFile(root *os.Root) (*os.File, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()

	name, err := windows.NewNTUnicodeString(lockFileName)
	if err != nil {
		return nil, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		RootDirectory: windows.Handle(dir.Fd()),
		ObjectName:    name,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	oa.Length = uint32(unsafe.Sizeof(oa))

	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateFile(
		&h,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.SYNCHRONIZE,
		&oa,
		&iosb,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		var status windows.NTStatus
		if errors.As(err, &status) {
			err = status.Errno()
		}
		return nil, &os.PathError{Op: "open", Path: lockFileName, Err: err}
	}
	return os.NewFile(uintptr(h), filepath.Join(root.Name(), lockFileName)), nil
}

func lockFile(fd uintptr, exclusive bool) error {
	var flag uint32 = windows.LOCKFILE_FAIL_IMMEDIATELY
	if exclusive {
		flag |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var ov windows.Overlapped // zero offset => start at 0
	h := windows.Handle(fd)
	err := windows.LockFileEx(h, flag, 0, maxBytes, maxBytes, &ov)
	if err != nil {
		return err
	}
	return nil
}

// releaseLock releases an advisory lock held on the given file using UnlockFileEx.
// The file is not closed.
func releaseLock(f *os.File) error {
	var ov windows.Overlapped // zero offset => start at 0
	h := windows.Handle(f.Fd())
	err := windows.UnlockFileEx(h, 0, maxBytes, maxBytes, &ov)
	if err != nil {
		return errors.Join(ErrUnlockUnsuccessful, err)
	}
	return nil
}

// unlockFile releases an advisory lock held on the given file using UnlockFileEx.
//
// The file is always closed before the function returns.
func unlockFile(f *os.File) error {
	defer func() { _ = f.Close() }()
	return releaseLock(f)
}
