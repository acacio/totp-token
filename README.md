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

```
secrets [
  { domain: "carta",
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
