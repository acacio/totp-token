# TOTP token generator tool

Reads ~/.totp-keys OR from command line.

## Usage

Using a provided Google Authenticator key in the command line:
```
# totp-token -k <SECRET>
```

Using a list of Google Authenticator secrets file under $HOME/.totp-keys:
```
# totp-token -d <DOMAIN>
```

Typical use:
```
# totp-token -d <DOMAIN> | pbcopy
# ssh <host>   (PASTE CMD-v)
```

The format of the .totp-keys file is a list of domain/secret pairs:

```
secrets [
  { domain: "interarma",
    key: "XXXXXXXXXXXX"
  },
  { domain: "gmail",
    key: "YYYYYYYYYYYY"
  },
  { domain: "e4",
    key: "YOUR GOOGLE_AUTHENTICATOR SECRET HERE"
  }
]
```
