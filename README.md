About Crypto Shortcuts
----------------------
This is a small wrapper library around ironclad and cl-base64 to provide quick and easy access to frequently used cryptography functionality like hashing, encoding and encrypting.

How To
------
```
(cryptos:from-base64 (cryptos:to-base64 "ＣＬがすごいです。"))

(cryptos:decrypt (cryptos:encrypt "Lispy Secrets, oooOOooo" "1234567890123456") "1234567890123456")

(cryptos:pbkdf2-hash "My passwords have never been this secure, whoa nelly!" "salty snacks")

(cryptos:simple-hash "I guess not everyone can afford PBKDF2." "crisps")

(cryptos:md5 "MD5 hashes are weak, but still sometimes useful.")

(cryptos:sha512 "If you don't need hash iterations or salts like simple-hash provides, this will do too.")

(cryptos:totp-uri "Someone")

(cryptos:totp "some secret key for the totp")
```

