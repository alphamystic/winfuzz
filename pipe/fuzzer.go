package pipe

import (
  "os"
	"fmt"
  core"github.com/alphamystic/winfuzz/core"
)

func SendPipeMsg(pipe string, msg []byte) ([]byte, error) {
	f, err := os.OpenFile(`\\.\pipe\`+pipe, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	_, err = f.Write(msg)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// Simple fuzz loop – inference engine feeds payloads
func FuzzPipe(
	target PipeTarget,
	payloads [][]byte,
	capture core.Telemetry,
) {

	for _, p := range payloads {
		before := capture

		_, err := SendPipeMsg(target.Name, p)
		if err != nil {
			continue
		}

		after := capture

		if bug := BuildPIPEBug(
			before,
			after,
			target.Name,
			"NamedPipe",
			target.Name,
			p,
		); bug != nil {
			bug.Report()
		}
	}
}
