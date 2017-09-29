package main

import (
	"./twofactor"
	"./secrets"
	"encoding/base32"
	"os/user"
	"io/ioutil"
	"fmt"
	"log"
	"flag"
  "github.com/golang/protobuf/proto"
)

func CHECK(e error) {
	if e != nil {
		panic(e)
	}
}

var verbose *bool

func parseArgs() (string) {

	keyPtr := flag.String("k", "", "Google Authenticator base32 secret")
	domainPtr := flag.String("d", "", "Use domain from ~/.totp-keys")
	verbose = flag.Bool("v", false, "Verbose.")
	flag.Parse()

  key := "undef"
  switch {
		case *keyPtr != "": { key = *keyPtr }
		case *domainPtr != "": {
			usr, err := user.Current()
			CHECK(err)
			data, err := ioutil.ReadFile(usr.HomeDir + "/.totp-keys")
			CHECK(err)
			totps := &secrets.TOTPSecrets{}
			if err := proto.UnmarshalText(string(data[:]), totps); err != nil {
				log.Fatalln("Failed to parse ~/.totp-keys:", err)
			}
			for _, secret  := range totps.Secrets {
				if secret.Domain == *domainPtr {
					key = secret.Key
					break
				}
			}
		}
		default: log.Fatal("You must provide either a key OR a domain in ~/.totp-keys")
	}
	if key == "undef" {
		log.Fatal("ERROR: Key not defined.")
	}
  return key
}

func main() {

	key := parseArgs()

	if *verbose { fmt.Println("Key: " + key) }
	binkey, err := base32.StdEncoding.DecodeString(key)
	CHECK(err)

	otp, err := twofactor.NewTOTPFromKey(binkey, "acacio@interarma.com", "InterArma", 6)
	CHECK(err)

	token := twofactor.CalculateTOTP(otp, 0)
	fmt.Println(token)
}
