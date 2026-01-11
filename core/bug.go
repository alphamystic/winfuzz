package core

import (
  "fmt"
)

type BugType int

const (
    BugArbitraryRead BugType = iota
    BugArbitraryWrite
    BugKernelPointerTrust
    BugUncheckedLength
    BugPrivilegedRegistryWrite
    BugPrivilegedProcessExec
    BugWeakACL
)

type Bug struct {
    Target     string
    Vector     string // IOCTL / NamedPipe
    Identifier string // IOCTL code / Pipe name
    Type       BugType
    Evidence   string
    Risk       string
    Repro      ReproCase
}

// Bug: Arbitrary Kernel Write
// IOCTL 0x8000202C trusted user-controlled pointer offsets (+0x20/+0x28/+0x30) and passed them to memmove without validation.

// Change this to be written into a file 
func (bug *Bug) Report() {
    fmt.Println("[!] BUG FOUND")
    fmt.Printf("Target: %s\n", bug.Target)
    fmt.Printf("Vector: %s (%s)\n", bug.Vector, bug.Identifier)
    fmt.Printf("Type:   %v\n", bug.Type)
    fmt.Printf("Risk:   %s\n", bug.Risk)
    fmt.Printf("Proof:  %s\n", bug.Evidence)

    //SavePocket(bug)
}
