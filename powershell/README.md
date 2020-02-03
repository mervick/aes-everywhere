# AES Everywhere - Cross Language Encryption Library

## Powershell

Cipher: AES/256/CBC/PKCS7Padding with random generated salt


### Depends on:
```
openssl
```

### Usage:
```raw
aes256 [-m encrypt (default)|decrypt] [-t text] [-p passphrase]
    [-i input_file] [-o output_file]
```

### Examples:

```powershell
# encrypt
pwsh ./aes256.ps1 -m encrypt -t "TEXT" -p "PASSWORD"
# from file to file
pwsh ./aes256.sh -m encrypt -p "PASSWORD" -i path/to/text-file -o path/to/encrypted-file

# decrypt
pwsh ./aes256.ps1 -m decrypt -t "ENCRYPTED" -p "PASSWORD"
# from file to file
pwsh ./aes256.sh -m decrypt -p "PASSWORD" -i path/to/encrypted -o path/to/text-file
```

### Using openssl:

```powershell
# encrypt
echo -n "TEXT" | openssl enc -aes-256-cbc -md md5 -a -A -pass pass:PASSWORD
# from file to file
openssl enc -aes-256-cbc -md md5 -a -A -pass pass:PASSWORD -in path/to/text-file -out path/to/encrypted-file

# decrypt
echo -n "ENCRYPTED" | openssl enc -aes-256-cbc -md md5 -a -A -pass pass:PASSWORD -d
# from file to file
openssl enc -aes-256-cbc -md md5 -a -A -pass pass:PASSWORD -in path/to/encrypted-file -out path/to/text-file -d

```
