# AES Everywhere - Cross Language Encryption Library

## Bash/shell wrapper

Cipher: AES/256/CBC/PKCS7Padding with random generated salt


### Depends on:
```
openssl
```

### Usage:
```raw
aes256 encrypt|decrypt [-p passphrase|--passphrase=passphrase]
    [-i input_file|--in=input_file] [-o output_file|--out=output_file]
    [-f format|--format=format]
```

### Examples:

```bash
# encrypt
echo -n "TEXT" | bash ./aes256.sh encrypt -p "PASSWORD"
# from file to file
bash ./aes256.sh encrypt -p "PASSWORD" --in path/to/text-file --out path/to/encrypted-file

# decrypt
echo -n "ENCRYPTED" | bash ./aes256.sh decrypt -p "PASSWORD"
# from file to file
bash ./aes256.sh decrypt -p "PASSWORD" --in path/to/encrypted-file --out path/to/text-file
```

### Using openssl:

```bash
# encrypt
echo -n "TEXT" | openssl enc -aes-256-cbc -md md5 -a -A -pass "pass:PASSWORD"
# from file to file
openssl enc -aes-256-cbc -md md5 -a -A -pass "pass:PASSWORD" -in path/to/text-file -out path/to/encrypted-file

# decrypt
echo -n "ENCRYPTED" | openssl enc -aes-256-cbc -md md5 -a -A -pass "pass:PASSWORD" -d
# from file to file
openssl enc -aes-256-cbc -md md5 -a -A -pass "pass:PASSWORD" -in path/to/encrypted-file -out path/to/text-file -d

```
