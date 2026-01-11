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
  core"github.com/alphamystic/winfuzz/core"
)




func RegistryChangedHKLM(before, after core.Telemetry) bool {
	return before.HKLMHash != after.HKLMHash
}

func CaptureHKLMHash() string {
	keys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		`HKLM\SYSTEM\CurrentControlSet\Services`,
	}

	h := sha256.New()
	for _, k := range keys {
		data := ReadRegistryKeyMetadata(k)
		h.Write([]byte(data))
	}

	return hex.EncodeToString(h.Sum(nil))
}


func SystemProcessSpawned(before, after core.Telemetry) bool {
	for pid := range after.SystemProcs {
		if _, ok := before.SystemProcs[pid]; !ok {
			return true
		}
	}
	return false
}



func CaptureSystemProcesses() map[int]string {
    procs := make(map[int]string)

    // Use Toolhelp32Snapshot or NtQuerySystemInformation
    for _, p := range EnumerateProcesses() {
        if p.User == "NT AUTHORITY\\SYSTEM" {
            procs[p.PID] = p.Image
        }
    }
    return procs
}



func EnumerateProcesses() []ProcessInfo {
	var results []ProcessInfo

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return results
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snap, &pe)
	if err != nil {
		return results
	}

	for {
		pid := pe.ProcessID
		image := windows.UTF16ToString(pe.ExeFile[:])

		user := resolveProcessUser(pid)

		results = append(results, ProcessInfo{
			PID:   int(pid),
			Image: image,
			User:  user,
		})

		err = windows.Process32Next(snap, &pe)
		if err != nil {
			break
		}
	}

	return results
}

func resolveProcessUser(pid uint32) string {
	hProc, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return "UNKNOWN"
	}
	defer windows.CloseHandle(hProc)

	var hToken windows.Token
	err = windows.OpenProcessToken(
		hProc,
		windows.TOKEN_QUERY,
		&hToken,
	)
	if err != nil {
		return "UNKNOWN"
	}
	defer hToken.Close()

	user, err := hToken.GetTokenUser()
	if err != nil {
		return "UNKNOWN"
	}

	sid := user.User.Sid

	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return "UNKNOWN"
	}

	return fmt.Sprintf("%s\\%s", domain, account)
}



func WeakACLDetected(before, after core.Telemetry) bool {
	for _, acl := range after.DeviceACLs {
		if strings.Contains(acl, "Everyone") &&
			(strings.Contains(acl, "WRITE") || strings.Contains(acl, "RW")) {
			return true
		}
	}
	return false
}



func ReadRegistryKeyMetadata(path string) string {
	root, subkey := splitRegistryPath(path)

	k, err := registry.OpenKey(
		root,
		subkey,
		registry.READ,
	)
	if err != nil {
		return ""
	}
	defer k.Close()

	var sb strings.Builder

	// Enumerate subkeys
	subkeys, err := k.ReadSubKeyNames(-1)
	if err == nil {
		for _, s := range subkeys {
			sb.WriteString("K:")
			sb.WriteString(s)
			sb.WriteRune(';')
		}
	}

	// Enumerate value names
	values, err := k.ReadValueNames(-1)
	if err == nil {
		for _, v := range values {
			sb.WriteString("V:")
			sb.WriteString(v)
			sb.WriteRune(';')
		}
	}

	return sb.String()
}

func splitRegistryPath(path string) (registry.Key, string) {
	switch {
  	case strings.HasPrefix(path, `HKLM\`):
  		return registry.LOCAL_MACHINE, strings.TrimPrefix(path, `HKLM\`)
  	case strings.HasPrefix(path, `HKEY_LOCAL_MACHINE\`):
  		return registry.LOCAL_MACHINE, strings.TrimPrefix(path, `HKEY_LOCAL_MACHINE\`)
  	default:
  		return 0, ""
	}
}


func BuildPIPEBug(
	tBefore, tAfter core.Telemetry,
	target, vector, id string,
	payload []byte,
) *core.Bug {

	if RegistryChangedHKLM(tBefore, tAfter) {
		return &core.Bug{
			Target:     target,
			Vector:     vector,
			Identifier: id,
			Type:       BugPrivilegedRegistryWrite,
			Evidence:   "SYSTEM process modified HKLM after unprivileged pipe input",
			Risk:       "Local Privilege Escalation",
			Repro: core.ReproCase{
				Action:  vector,
				Target:  target,
				Payload: payload,
				Meta: map[string]string{
					"effect": "HKLM modified",
				},
			},
		}
	}

	if SystemProcessSpawned(tBefore, tAfter) {
		return &core.Bug{
			Target:     target,
			Vector:     vector,
			Identifier: id,
			Type:       BugPrivilegedProcessExec,
			Evidence:   "New SYSTEM process spawned after pipe request",
			Risk:       "Arbitrary code execution as SYSTEM",
			Repro: core.ReproCase{
				Action:  vector,
				Target:  target,
				Payload: payload,
			},
		}
	}

	if WeakACLDetected(tBefore, tAfter) {
		return &core.Bug{
			Target:     target,
			Vector:     vector,
			Identifier: id,
			Type:       BugWeakACL,
			Evidence:   "Named Pipe allows Everyone RW access",
			Risk:       "Unauthorized access to privileged IPC",
		}
	}

	return nil
}
