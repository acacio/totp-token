/*
Copyright 2021 Acacio Cruz acacio@acacio.coom

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"github.com/acacio/totp-token/secrets"
	"github.com/acacio/totp-token/twofactor"
	"os"
	"strings"

	"encoding/base32"
	"flag"
	"fmt"
	"os/user"

	"google.golang.org/protobuf/encoding/prototext"
)

var verbose *bool

func parseArgs() string {

	keyPtr := flag.String("k", "", "Google Authenticator base32 secret")
	domainPtr := flag.String("d", "", "Use domain from ~/.totp-keys")
	verbose = flag.Bool("v", false, "Verbose.")
	flag.Parse()

	key := "undef"
	switch {
	case *keyPtr != "":
		{
			key = *keyPtr
		}
	case *domainPtr != "":
		{
			usr, err := user.Current()
			if err != nil {
				fmt.Println("Can't get current user info", err.Error())
				os.Exit(1)
			}

			data, err := os.ReadFile(usr.HomeDir + "/.totp-keys")
			if err != nil {
				fmt.Println("Can't get current user homedir", err.Error())
				os.Exit(2)
			}

			totps := &secrets.TOTPSecrets{}
			if err := prototext.Unmarshal(data[:], totps); err != nil {
				fmt.Println("Failed to parse ~/.totp-keys:", err)
				os.Exit(3)
			}
			for _, secret := range totps.Secrets {
				if secret.Domain == *domainPtr {
					key = secret.Key
					break
				}
			}
		}
	default:
		fmt.Println("You must provide either a key OR a domain in ~/.totp-keys")
		os.Exit(3)
	}
	if key == "undef" {
		fmt.Println("ERROR: Key not defined.")
		os.Exit(3)
	}
	return key
}

func main() {
	key := parseArgs()

	if *verbose {
		fmt.Println("Key: " + key)
	}
	binkey, err := base32.StdEncoding.DecodeString(key)
	if err != nil {
		if len(key) != 32 { // Sometimes keys miss their padding.
			// Try again after adding ==== padding at the end.
			newkey := key + strings.Repeat("=", 32-len(key))
			binkey, err = base32.StdEncoding.DecodeString(newkey)
		}
		if err != nil {
			fmt.Println("Please try to check your key", err.Error())
			os.Exit(4)
		}
	}

	otp, err := twofactor.NewTOTPFromKey(binkey, "acacio@interarma.com", "InterArma", 6)
	if err != nil {
		fmt.Println("error generating TOTP:", err.Error())
		os.Exit(5)
	}

	token := twofactor.CalculateTOTP(otp, 0)
	fmt.Println(token)
}
