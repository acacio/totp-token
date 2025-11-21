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
	"os"
	"strings"

	"github.com/acacio/totp-token/secrets"
	"github.com/acacio/totp-token/twofactor"

	"encoding/base32"
	"flag"
	"fmt"
	"os/user"

	"google.golang.org/protobuf/encoding/prototext"
)

var verbose *bool

func readSecrets(homeDir string) (*secrets.TOTPSecrets, error) {
	data, err := os.ReadFile(homeDir + "/.totp-keys")
	if err != nil {
		return nil, fmt.Errorf("can't get current user homedir: %w", err)
	}

	totps := &secrets.TOTPSecrets{}
	if err := prototext.Unmarshal(data[:], totps); err != nil {
		return nil, fmt.Errorf("failed to parse ~/.totp-keys: %w", err)
	}
	return totps, nil
}

func loadConfig(keyPtr, domainPtr string, homeDir string) (string, error) {
	key := "undef"
	switch {
	case keyPtr != "":
		{
			key = keyPtr
		}
	case domainPtr != "":
		{
			totps, err := readSecrets(homeDir)
			if err != nil {
				return "", err
			}
			for _, secret := range totps.Secrets {
				if secret.Domain == domainPtr {
					key = secret.Key
					break
				}
			}
		}
	default:
		return "", fmt.Errorf("you must provide either a key OR a domain in ~/.totp-keys")
	}
	if key == "undef" {
		return "", fmt.Errorf("key not defined")
	}
	return key, nil
}

func main() {
	keyPtr := flag.String("k", "", "Google Authenticator base32 secret")
	domainPtr := flag.String("d", "", "Use domain from ~/.totp-keys")
	listPtr := flag.Bool("l", false, "List all available keys")
	verbose = flag.Bool("v", false, "Verbose.")
	flag.Parse()

	usr, err := user.Current()
	if err != nil {
		fmt.Println("Can't get current user info", err.Error())
		os.Exit(1)
	}

	if *listPtr {
		totps, err := readSecrets(usr.HomeDir)
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
		for _, secret := range totps.Secrets {
			fmt.Println(secret.Domain)
		}
		return
	}

	key, err := loadConfig(*keyPtr, *domainPtr, usr.HomeDir)
	if err != nil {
		fmt.Println(err)
		os.Exit(3)
	}

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
