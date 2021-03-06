package main

import (
	"code.google.com/p/go.crypto/pbkdf2"
	"code.google.com/p/gopass"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/atotto/clipboard"
	"io"
	"io/ioutil"
	"os/user"
	"path/filepath"
)

const (
	alphanum    = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	READ        = "read"
	ADD         = "add"
	LISTKEYS    = "listkeys"
	PASSWORD_DB = ".config/passwords.json"
)

var (
	file      string
	logins    map[string]Password
	key       []byte
	operation string
)

type Password struct {
	Pass []byte
	Salt []byte
}

func readdb() error {
	db, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	if len(db) == 0 {
		logins = make(map[string]Password)
		return nil
	}
	return json.Unmarshal(db, &logins)
}

func savedb() error {
	db, err := json.MarshalIndent(logins, "", "\t")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(file, db, 0)
	if err != nil {
		return err
	}

	return nil
}

func add(name string, password []byte) error {
	clipboard.WriteAll(string(password))

	p := Password{}
	p.Salt = randBytes(8)

	key = pbkdf2.Key(key, p.Salt, 4096, 32, sha1.New)

	session, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	password = pad(password)

	pass_ciphered := make([]byte, aes.BlockSize+len(password))
	iv := pass_ciphered[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	mode := cipher.NewCBCEncrypter(session, iv)
	mode.CryptBlocks(pass_ciphered[aes.BlockSize:], password)
	p.Pass = pass_ciphered

	logins[name] = p
	return nil
}

func read(name string) error {
	p, ok := logins[name]

	if !ok {
		return fmt.Errorf("no such key")
	}
	key = pbkdf2.Key(key, p.Salt, 4096, 32, sha1.New)
	session, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	pass_ciphered := p.Pass
	iv := pass_ciphered[:aes.BlockSize]
	pass_ciphered = pass_ciphered[aes.BlockSize:]

	pass_plain := make([]byte, len(pass_ciphered))
	mode := cipher.NewCBCDecrypter(session, iv)
	mode.CryptBlocks(pass_plain, pass_ciphered)

	clipboard.WriteAll(string(pass_plain))
	return nil
}

func randBytes(n int) []byte {
	var bytes = make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return bytes
}

func del(name string) {
	delete(logins, name)
}

func pad(input []byte) []byte {
	if len(input)%aes.BlockSize == 0 {
		return input
	}

	out := make([]byte, 32)
	copy(out, input)
	return out
}

func listkeys() {
	for key, _ := range logins {
		fmt.Println(key)
	}
}

func main() {
	usr, _ := user.Current()
	file = filepath.Join(usr.HomeDir, PASSWORD_DB)

	var operation, name, pass_ string
	var length int
	var pass []byte

	flag.StringVar(&operation, "o", "read", "operations: read / add / listkeys")
	flag.StringVar(&name, "n", "name", "key name")
	flag.IntVar(&length, "l", 16, "key length")
	flag.StringVar(&pass_, "p", "", "password to add")
	flag.Parse()

	if pass_ == "" {
		pass = randBytes(length)

	} else {
		pass = []byte(pass_)
	}

	key_, err := gopass.GetPass("Session Key ")
	if err != nil {
		panic(err)
	}
	key = []byte(key_)

	err = readdb()
	if err != nil {
		panic(err)
	}

	if operation == READ {
		err := read(name)
		if err != nil {
			panic(err)
		}
	}
	if operation == ADD {
		err := add(name, pass)
		if err != nil {
			panic(err)
		}

		err = savedb()
		if err != nil {
			panic(err)
		}
	}
	if operation == LISTKEYS {
		listkeys()
	}
}
