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
   #:to
   #:code
   ;; hashing.lisp
   #:make-salt
   #:pbkdf2-key
   #:pbkdf2-hash
   #:simple-hash
   #:rfc-2307-hash
   #:check-rfc-2307-hash))
(in-package #:org.shirakumo.crypto-shortcuts)
