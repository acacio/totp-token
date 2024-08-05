[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Facacio%2Ftotp-token.svg?type=small)](https://app.fossa.com/projects/git%2Bgithub.com%2Facacio%2Ftotp-token?ref=badge_large)

# TOTP token generator tool

This tool can replace Google Authenticator and easily generate several secrets.

Reads `~/.totp-keys` as it's config (so keep that file readable just by you).

## Usage

Using a provided Google Authenticator key in the command line:
```
totp-token -k <SECRET>
```

Using a list of Google Authenticator secrets file under $HOME/.totp-keys:
```
totp-token -d <DOMAIN>
```

Typical use:
```
totp-token -d <DOMAIN> | pbcopy
ssh <host>   (PASTE CMD-v)
```

The format of the .totp-keys file is a list of domain/secret pairs:
Note that the keys need to be capitalized (although some domains give you keys with lowercase characters).

Note: url, for now, is for documentation purposes only but might be useful inthe future.

```
secrets [
  { domain: "carta",
    url: "otpauth://totp/Microsoft:blabla@live.com?secret=XXXXXXXXXXXXXXXX&issuer=Microsoft",
    key: "XXXXXXXXXXXX"
  },
  { domain: "gmail",
    key: "YYYYYYYYYYYY"
  },
  { domain: "dropbox",
    key: "YOUR GOOGLE_AUTHENTICATOR SECRET HERE"
  }
]
```

# Testing
[![Coverage Status](https://coveralls.io/repos/github/acacio/totp-token/badge.svg?branch=master)](https://coveralls.io/github/acacio/totp-token?branch=master)


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Facacio%2Ftotp-token.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Facacio%2Ftotp-token?ref=badge_large)

