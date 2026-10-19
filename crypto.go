package guard

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// Fernet uses exactly the legacy Python key derivation and token format.
type fernet struct{ key [32]byte }

func newFernet(secret string) fernet { return fernet{sha256.Sum256([]byte(secret))} }
func (f fernet) encrypt(plain []byte) string {
	block, _ := aes.NewCipher(f.key[16:])
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	token := make([]byte, 25+len(padded))
	token[0] = 0x80
	binary.BigEndian.PutUint64(token[1:9], uint64(time.Now().Unix()))
	if _, err := rand.Read(token[9:25]); err != nil {
		panic(err)
	}
	cipher.NewCBCEncrypter(block, token[9:25]).CryptBlocks(token[25:], padded)
	mac := hmac.New(sha256.New, f.key[:16])
	mac.Write(token)
	token = append(token, mac.Sum(nil)...)
	return base64.URLEncoding.EncodeToString(token)
}
func (f fernet) decrypt(value string) ([]byte, error) {
	invalid := errors.New("encrypted data could not be read; verify APP_SECRET")
	token, err := base64.URLEncoding.DecodeString(value)
	if err != nil || len(token) < 73 || token[0] != 0x80 || (len(token)-57)%16 != 0 {
		return nil, invalid
	}
	body := token[:len(token)-32]
	mac := hmac.New(sha256.New, f.key[:16])
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), token[len(token)-32:]) {
		return nil, invalid
	}
	block, _ := aes.NewCipher(f.key[16:])
	plain := make([]byte, len(body)-25)
	cipher.NewCBCDecrypter(block, body[9:25]).CryptBlocks(plain, body[25:])
	n := int(plain[len(plain)-1])
	if n < 1 || n > 16 || n > len(plain) || !bytes.Equal(plain[len(plain)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, invalid
	}
	return plain[:len(plain)-n], nil
}

func pythonJSONString(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 || r > 126 {
				if r > 0xffff {
					a, z := utf16.EncodeRune(r)
					fmt.Fprintf(&b, `\u%04x\u%04x`, a, z)
				} else {
					fmt.Fprintf(&b, `\u%04x`, r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
func authRevision(c Config) string {
	mac := hmac.New(sha256.New, []byte(c.AppSecret))
	mac.Write([]byte("[" + pythonJSONString(c.Username) + ", " + pythonJSONString(c.Password) + "]"))
	return hex.EncodeToString(mac.Sum(nil))
}
func digest(value string) string { h := sha256.Sum256([]byte(value)); return hex.EncodeToString(h[:]) }
func uid() string {
	var v [16]byte
	if _, e := rand.Read(v[:]); e != nil {
		panic(e)
	}
	v[6] = (v[6] & 15) | 64
	v[8] = (v[8] & 63) | 128
	h := hex.EncodeToString(v[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
