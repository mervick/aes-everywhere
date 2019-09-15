# AES Everywhere - Cross Language Encryption Library

## JavaScript implementation

Cipher: AES/256/CBC/PKCS7Padding with random generated salt

Works well both on the browsers and on the node.js
Compatible with **React-native**

### Browser

Add to your html page
```html
<script src="path/to/aes-everywhere/javascript/dist/aes256.min.js"></script>
```

Usage:
```js
// encryption
var encrypted = AES256.encrypt('TEXT', 'PASSWORD');
console.log(encrypted);

// decryption
console.log(AES256.decrypt(encrypted, 'PASSWORD'));
```


### node.js

Installation:
```
npm install aes-everywhere
```

Usage:
```js
var AES256  = require('aes-everywhere');
// or
// import AES256 from 'aes-everywhere';

// encryption
var encrypted = AES256.encrypt('TEXT', 'PASSWORD')
console.log(encrypted);

// decryption
console.log(AES256.decrypt(encrypted, 'PASSWORD'));

```


### ECMAScript6 and above

```js
import AES256 from 'aes-everywhere';

// encryption
const encrypted = AES256.encrypt('TEXT', 'PASSWORD');
console.log(encrypted);

// decryption
console.log(AES256.decrypt(encrypted, 'PASSWORD'));
```
