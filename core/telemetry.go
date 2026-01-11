package core

type Telemetry struct {
    HKLMHash        string
    SystemProcs     map[int]string // PID -> Image
    DeviceACLs      map[string]string
    LastError       error
}
