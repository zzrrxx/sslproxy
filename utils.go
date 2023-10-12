package sslproxy

import (
	"fmt"
	"strings"
)

func ToHexDump(data []byte) string {
	length := len(data)
	if length == 0 {
		return ""
	}

	hexDigits := []byte{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' }

	out := strings.Builder{}
	len16 := (length + 15) / 16 * 16
	for i := 0; i < len16; i++ {

		curLine := []byte("                                                                   ") // length: 67
		for j := 0; j < 16; j++ {
			c := data[i]
			pos1 := j * 3
			pos2 := 51 + j

			curLine[pos1] = hexDigits[(c & 0xf0) >> 4]
			curLine[pos1 + 1] = hexDigits[(c & 0x0f)]
			if c < 0x20 || c > 0x7E {
				curLine[pos2] = '.'
			} else {
				curLine[pos2] = c
			}
		}

		out.WriteString(fmt.Sprintf("%04x", i - 16))
		out.WriteString("  ")
		out.Write(curLine)
		if i < length {
			out.WriteString("\r\n")
		}
	}

	return out.String()
}
