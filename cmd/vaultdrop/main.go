package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wuser-lab/vaultdrop/internal/vault"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "encrypt":
		crypt(os.Args[2:], true)
	case "decrypt":
		crypt(os.Args[2:], false)
	default:
		usage()
	}
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", ".", "output directory")
	fs.Parse(args)
	priv, pub, err := vault.GenerateKeyPair(3072)
	check(err)
	check(os.MkdirAll(*out, 0700))
	check(os.WriteFile(filepath.Join(*out, "vaultdrop-private.pem"), priv, 0600))
	check(os.WriteFile(filepath.Join(*out, "vaultdrop-public.pem"), pub, 0644))
	fmt.Println("key pair written to", *out)
}

func crypt(args []string, encrypt bool) {
	fs := flag.NewFlagSet("crypt", flag.ExitOnError)
	key := fs.String("key", "", "PEM key file")
	in := fs.String("in", "", "input file")
	out := fs.String("out", "", "output file")
	name := fs.String("name", "", "authenticated logical filename")
	fs.Parse(args)
	if *key == "" || *in == "" || *out == "" {
		fs.Usage()
		os.Exit(2)
	}
	keyBytes, err := os.ReadFile(*key)
	check(err)
	input, err := os.ReadFile(*in)
	check(err)
	if *name == "" {
		*name = filepath.Base(*in)
	}
	var result []byte
	if encrypt {
		result, err = vault.Encrypt(keyBytes, input, []byte(*name))
	} else {
		result, err = vault.Decrypt(keyBytes, input, []byte(*name))
	}
	check(err)
	check(os.WriteFile(*out, result, 0600))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "vaultdrop:", err)
		os.Exit(1)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: vaultdrop <keygen|encrypt|decrypt> [flags]")
	os.Exit(2)
}
