package core

type ReproCase struct {
    Action   string            // ioctl | pipe
    Target   string
    Payload  []byte
    Meta     map[string]string
}

func Replay(repro ReproCase) {
    fmt.Println("[*] Replaying repro case")

    switch repro.Action {
    case "ioctl":
        FuzzIOCTL(repro.Target, parseIOCTL(repro.Meta), repro.Payload)
    case "pipe":
        SendPipeMsg(repro.Target, repro.Payload)
    }
}
