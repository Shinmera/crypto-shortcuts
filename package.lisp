(in-package #:cl-user)
(defpackage #:crypto-shortcuts
  (:nicknames #:org.shirakumo.crypto-shortcuts #:cryptos)
  (:use #:cl)
  (:export
   ;; crypto.lisp
   #:normalize-key
   #:get-cipher
   #:encrypt
   #:decrypt
   #:hmac
   #:cmac
   ;; digests.lisp
   ;; auto-export
   #:find-digest
   ;; encode.lisp
   #:to-octets
   #:to-string
   #:to-hex
   #:from-hex
   #:to-base64
   #:from-base64
   #:to-base32
   #:from-base32
   #:to
   #:code
   ;; hashing.lisp
   #:make-salt
   #:pbkdf2-key
   #:pbkdf2-hash
   #:simple-hash
   #:rfc-2307-hash
   #:check-rfc-2307-hash
   ;; totp.lisp
   #:totp
   #:totp-uri
   #:decode-totp-uri))
(in-package #:org.shirakumo.crypto-shortcuts)
