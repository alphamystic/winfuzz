package ioctl


// IOCTL References:
   // http://www.ioctls.net/
   // Vulnerable Drivers: https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
   // https://dl.acm.org/doi/pdf/10.1145/3564625.3564631
//
type IoctlPayload struct {
    Header  [0x20]byte // filler / flags / version
    DstPtr  uint64     // +0x20
    SrcPtr  uint64     // +0x28
    Size    uint64     // +0x30
    Padding [0x100]byte
}
