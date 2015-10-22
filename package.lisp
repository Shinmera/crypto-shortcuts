#|
 This file is a part of Crypto-Shortcuts
 (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:cl-user)
(defpackage #:crypto-shortcuts
  (:nicknames #:org.shirakumo.crypto-shortcuts #:cryptos)
  (:use #:cl)
  (:export
   ;; crypto.lisp
   #:get-cipher
   #:encrypt
   #:decrypt
   #:hmac
   #:cmac
   ;; digests.lisp
   #:md4
   #:sha1
   #:md5
   #:crc24
   #:adler32
   #:tiger
   #:sha256
   #:ripemd-128
   #:ripemd-160
   #:crc32
   #:whirlpool
   #:sha224
   #:sha512
   #:sha384
   #:md2
   #:tree-hash
   ;; encode.lisp
   #:to-octets
   #:to-string
   #:to-hex
   #:from-hex
   #:to-base64
   #:from-base64
   ;; hashing.lisp
   #:make-salt
   #:pbkdf2-key
   #:pbkdf2-hash
   #:simple-hash))
(in-package #:org.shirakumo.crypto-shortcuts)
