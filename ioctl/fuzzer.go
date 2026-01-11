package ioctl

import (
    "syscall"
    "unsafe"
)

const (
    GENERIC_READ  = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
)

func FuzzIOCTL(device string, ioctl uint32, payload []byte) error {
    path := `\\.\` + device

    h, err := syscall.CreateFile(
        syscall.StringToUTF16Ptr(path),
        GENERIC_READ|GENERIC_WRITE,
        0,
        nil,
        OPEN_EXISTING,
        0,
        0,
    )
    if err != nil {
        return err
    }
    defer syscall.CloseHandle(h)

    var returned uint32
    return syscall.DeviceIoControl(
        h,
        ioctl,
        &payload[0],
        uint32(len(payload)),
        &payload[0],
        uint32(len(payload)),
        &returned,
        nil,
    )
}


func RunIOCTLFuzz(device string, ioctls []uint32) {
    for _, code := range ioctls {
        payload := BuildArbRWPayload()
        before := CaptureTelemetry()

        err := FuzzIOCTL(device, code, payload)
        after := CaptureTelemetry()

        AnalyzeDelta(code, before, after, err)
    }
}
