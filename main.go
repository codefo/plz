package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"net/mail"
	"net/url"
	"strings"

	"github.com/alexflint/go-arg"
	"golang.org/x/crypto/sha3"
)

const PLZ_VERSION = "0.1.0"

type Email struct {
	Local  string
	Domain string
}

func (e *Email) String() string {
	return fmt.Sprintf("%s@%s", e.Local, e.Domain)
}

func (e *Email) UnmarshalText(b []byte) error {
	email, err := mail.ParseAddress(string(b))

	if err != nil {
		return fmt.Errorf("unable to parse email")
	}

	parts := strings.Split(email.Address, "@")

	if len(parts) != 2 {
		return fmt.Errorf("unable to parse email")
	}

	e.Local = parts[0]
	e.Domain = parts[1]

	return nil
}

type URL struct {
	Host string
}

func (u *URL) UnmarshalText(b []byte) error {
	rawURL := string(b)

	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)

	if err != nil {
		return fmt.Errorf("unable to parse URL")
	}

	u.Host = parsedURL.Host

	return nil
}

type Args struct {
	URL       URL    `arg:"required,positional" help:"could be any valid URL"`
	Email     Email  `arg:"-e,--,required,env:PLZ_EMAIL" help:"email address which you want to extend with a suffix"`
	Secret    string `arg:"-s,--,required,env:PLZ_SECRET" help:"secret that makes the suffix unique and secure"`
	Function  string `arg:"-,--func,env:PLZ_FUNC" help:"function for the hash generation, one of: sha1, sha2, sha3" default:"sha3"`
	Length    int    `arg:"-,--len,env:PLZ_LEN" help:"length of the suffix in bytes, beween 1 and 20" default:"8"`
	Separator string `arg:"-,--sep,env:PLZ_SEP" help:"separator between a host and a hash in the suffix" default:"-"`
}

func (Args) Version() string {
	return fmt.Sprintf("plz %s", PLZ_VERSION)
}

func (Args) Epilogue() string {
	return "For more information, please visit https://github.com/codefo/plz"
}

func reverseDomain(host string) string {
	var parts = strings.Split(host, ".")

	if len(parts) > 0 && parts[0] == "www" {
		parts = parts[1:]
	}

	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	return strings.Join(parts, ".")
}

func calculateHash(function string, secret string, domain string, email string) string {
	var hash hash.Hash

	switch function {
	case "sha1":
		hash = sha1.New()
	case "sha2":
		hash = sha256.New()
	default:
		hash = sha3.New512()
	}

	io.WriteString(hash, secret)
	io.WriteString(hash, domain)
	io.WriteString(hash, email)

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func main() {
	var args Args
	p := arg.MustParse(&args)

	if args.Function != "sha1" && args.Function != "sha2" && args.Function != "sha3" {
		p.Fail("incorrect function, use one of: sha1, sha2, sha3")
	}

	if args.Length <= 0 || args.Length > 20 {
		p.Fail("length must be between 1 and 20")
	}

	domain := reverseDomain(args.URL.Host)
	hash := calculateHash(args.Function, args.Secret, domain, args.Email.String())
	suffix := strings.Join([]string{domain, hash[:2*args.Length]}, args.Separator)

	email := &Email{
		Local:  strings.Join([]string{args.Email.Local, suffix}, "+"),
		Domain: args.Email.Domain,
	}

	fmt.Println(email.String())
}
