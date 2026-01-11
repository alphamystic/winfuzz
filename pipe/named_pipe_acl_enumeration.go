package pipe

import (
	"fmt"
  "unsafe"
	"strings"
  "syscall"
  "encoding/hex"
  "crypto/sha256"
  "golang.org/x/sys/windows"
  "golang.org/x/sys/windows/registry"
)


func GetPipeACLWin32(pipeName string) (*PipeACL, error) {
	full := `\\.\pipe\` + pipeName
	obj, err := windows.UTF16PtrFromString(full)
	if err != nil {
		return nil, err
	}

	var sd *windows.SECURITY_DESCRIPTOR
	err = windows.GetNamedSecurityInfo(
		obj,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
		nil,
		nil,
		nil,
		nil,
		&sd,
	)
	if err != nil {
		return nil, err
	}

	return parseSecurityDescriptor(sd)
}


var (
	ntdll                   = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySecurityObject = ntdll.NewProc("NtQuerySecurityObject")
)

func GetPipeACLNt(pipeName string) (*PipeACL, error) {
	path := `\\.\pipe\` + pipeName
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, 8192)
	var retLen uint32

	r, _, _ := procNtQuerySecurityObject.Call(
		uintptr(h),
		uintptr(windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
	)

	if r != 0 {
		return nil, syscall.Errno(r)
	}

	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buf[0]))
	return parseSecurityDescriptor(sd)
}


func GetPipeACLFileFallback(pipeName string) (*PipeACL, error) {
	path := `\\.\pipe\` + pipeName

	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	var sd *windows.SECURITY_DESCRIPTOR
	err = windows.GetSecurityInfo(
		h,
		windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
		nil,
		nil,
		nil,
		nil,
		&sd,
	)
	if err != nil {
		return nil, err
	}

	return parseSecurityDescriptor(sd)
}


func parseSecurityDescriptor(sd *windows.SECURITY_DESCRIPTOR) (*PipeACL, error) {
	var owner *windows.SID
	_, _, err := sd.Owner()
	if err == nil {
		owner, _, _ = sd.Owner()
	}

	var acl *windows.ACL
	_, _, err = sd.DACL()
	if err != nil || acl == nil {
		return &PipeACL{Owner: "UNKNOWN"}, nil
	}

	var entries []ACEEntry
	for i := uint32(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		err = windows.GetAce(acl, i, (*unsafe.Pointer)(unsafe.Pointer(&ace)))
		if err != nil {
			continue
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		name, domain, _, _ := sid.LookupAccount("")
		entries = append(entries, ACEEntry{
			Trustee: domain + `\` + name,
			Rights:  fmt.Sprintf("0x%x", ace.Mask),
		})
	}

	return &PipeACL{
		Owner: ownerString(owner),
		DACL:  entries,
	}, nil
}


func InspectPipeACL(pipe string) *PipeACL {
	if acl, err := GetPipeACLWin32(pipe); err == nil {
		return acl
	}
	if acl, err := GetPipeACLNt(pipe); err == nil {
		return acl
	}
	if acl, err := GetPipeACLFileFallback(pipe); err == nil {
		return acl
	}
	return nil
}
