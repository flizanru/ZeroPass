package gui

import (
	"crypto/rand"
	"fmt"
)

const pwCharset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"0123456789" +
	"!#$%&()*+-/=?@[]^_{|}~"

func generatePassword(n int) ([]byte, error) {
	out := make([]byte, n)
	limit := 256 - 256%len(pwCharset)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("CSPRNG недоступен: %w", err)
		}
		if int(buf[0]) < limit {
			out[i] = pwCharset[int(buf[0])%len(pwCharset)]
			i++
		}
	}
	return out, nil
}
