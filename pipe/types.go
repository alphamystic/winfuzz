package pipe


type PipeTarget struct {
	Name string
	ACL  string
}

type PipeHeader struct {
	Magic   uint32
	Version uint32
	Opcode  uint32
	InLen   uint32
	OutLen  uint32
}

type ProcessInfo struct {
	PID   int
	Image string
	User  string
}

type PipeACL struct {
	Owner string
	DACL  []ACEEntry
	Raw   string
}

type ACEEntry struct {
	Trustee string
	Rights  string
}
