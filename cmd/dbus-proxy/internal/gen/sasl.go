package gen

import (
	"encoding/hex"
	"strconv"
	"strings"

	"pgregory.net/rapid"
)

// SASL draws what a client sends to authenticate: a nul or another first byte, then commands in any order (AUTH with
// EXTERNAL or another mechanism, with the right uid, another, or bad hex, DATA, BEGIN, CANCEL, ERROR,
// NEGOTIATE_UNIX_FD), lowercase and unknown ones, random bytes, lines past 16 KiB and past the count, each ended by
// CRLF but perhaps the last
func SASL(uid int) *rapid.Generator[[]byte] {
	own := hex.EncodeToString([]byte(strconv.Itoa(uid)))
	other := hex.EncodeToString([]byte(strconv.Itoa(uid + 1)))
	return rapid.Custom(func(t *rapid.T) []byte {
		out := []byte{0}
		if rapid.IntRange(0, 19).Draw(t, "first") == 0 {
			out[0] = rapid.Byte().Draw(t, "byte")
		}
		id := rapid.SampledFrom([]string{own, own, "", other, "zz", "0" + own, strings.ToUpper(own)})
		n := rapid.IntRange(0, 40).Draw(t, "lines")
		for i := range n {
			var line string
			switch rapid.IntRange(0, 13).Draw(t, "kind") {
			case 0, 1:
				line = "AUTH EXTERNAL " + id.Draw(t, "id")
			case 2:
				line = "AUTH EXTERNAL"
			case 3:
				line = "AUTH " + rapid.SampledFrom([]string{"ANONYMOUS", "DBUS_COOKIE_SHA1", "", "external"}).Draw(t, "mech")
			case 4:
				line = "DATA " + id.Draw(t, "id")
			case 5:
				line = "DATA"
			case 6, 7:
				line = "BEGIN"
			case 8:
				line = rapid.SampledFrom([]string{"CANCEL", "ERROR", "ERROR some text"}).Draw(t, "cancel")
			case 9:
				line = "NEGOTIATE_UNIX_FD"
			case 10:
				line = rapid.SampledFrom([]string{"auth EXTERNAL", "STARTTLS", "OK 1234", "", " AUTH"}).Draw(t, "odd")
			case 11:
				line = string(rapid.SliceOfN(rapid.Byte(), 0, 32).Draw(t, "bytes"))
			case 12:
				line = "AUTH EXTERNAL " + strings.Repeat("3", rapid.SampledFrom([]int{16<<10 - 14, 16<<10 - 13, 16 << 10}).Draw(t, "long"))
			default:
				line = "AUTH EXTERNAL " + own
			}
			out = append(out, line...)
			if i < n-1 || rapid.IntRange(0, 9).Draw(t, "crlf") > 0 {
				out = append(out, '\r', '\n')
			}
		}
		return out
	})
}
