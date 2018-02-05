# Aes Everywhere - Cross language encryption library

## JavaScript version

Cipher: AES/256/CBC/PKCS5Padding with random generated salt

Works well both on the browsers and on the node.js

### Browser

Add to your html page
```html
<script src="path/to/aes-everywhere/javascript/dist/aes256.min.js"></script>
```

Usage:
```js
// encryption
console.log(AES256.encrypt('TEXT', 'PASSWORD'));

// decryption
console.log(AES256.decrypt('ENCRYPTED", 'PASSWORD'));
```


### node.js

Installation:
```
npm install aes-everywhere
```

Usage:
```js
import AES256 from 'aes-everywhere';

// encryption
console.log(AES256.encrypt('TEXT', 'PASSWORD'));

// decryption
console.log(AES256.decrypt('ENCRYPTED", 'PASSWORD'));

```
