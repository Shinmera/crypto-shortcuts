#|
 This file is a part of Crypto-Shortcuts
 (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.crypto-shortcuts)

(defmacro setdocs (&body pairs)
  `(progn
     ,@(loop for (var doc) in pairs
             collect (destructuring-bind (var &optional (type 'function))
                         (if (listp var) var (list var))
                       `(setf (documentation ',var ',type) ,doc)))))

;; crypto.lisp
(setdocs
  (get-cipher
   "Return the corresponding cipher with KEY using MODE and potentially the initialization-vector IV.")

  (encrypt
   "Encrypt TEXT with KEY using the provided CIPHER/MODE/IV.
Depending on the mode, the key should be of length 16, 32, or 64.
The returned encrypted vector is encoded by the format specified in TO.

The default cipher is AES, default mode is ECB, and default TO is BASE64.

Four values are returned: Encrypted&encoded text, key, cipher, mode, and IV.

See TO")
  
  (decrypt
   "Decrypt TEXT with KEY using the provided CIPHER/MODE/IV.
Depending on the mode, the key should be of length 16, 32, or 64.
The passed text is decoded by the format specified in FROM.

The default cipher is AES, default mode is ECB, and default TO is BASE64.

Four values are returned: Decrypted text, key, cipher, mode, and IV.

See CODE")

  (hmac
   "Generate an HMAC digest of TEXT using KEY and the provided DIGEST method.
The returned digest is encoded by the format specified in TO.

The default digest is SHA512, and default TO is BASE64.

Three values are returned: digest, key, and digest-type.

See TO")

  (cmac
   "Generate a CMAC digest of TEXT using KEY and the provided CIPHER/MODE/IV.
The returned digest is encoded by the format specified in TO.

The default cipher is AES, default mode is ECB, and default TO is BASE64.

Four values are returned: digest, key, cipher, mode, and IV.

See To"))

;; digests.lisp
;; In-source.

;; encode.lisp
(setdocs
  (to-octets
   "Turns STRING into a FORMAT (default UTF-8) encoded octet-vector.")
  (to-string
   "Turns OCTETS from FORMAT (default UTF-8) encoding into a string. ")

  (to-hex
   "Turn VECTOR into a hex-string.")

  (from-hex
   "Turn the hex-string into an octet-vector.")

  (to-base64
   "Turns a vector into a base64-encoded string.")
  
  (from-base64
   "Turns a base64-encoded vector into a vector encoded by TO.
See TO.")

  (to
   "Convenience function to call the various encoders.
By default, THING can be one of:

NIL      -- Returns VECTOR
:OCTETS  -- See TO-OCTETS
:STRING  -- See TO-STRING
:HEX     -- See TO-HEX
:BASE64  -- See TO-BASE64")

  (code
   "Convenience function to de/encode in one pass.
By default, FROM and TO can both be one of:

:OCTETS :STRING :HEX :BASE64

If FROM is NIL, then TO is called with the remaining arguments."))

;; hashing.lisp
(setdocs
  (make-salt
   "Create a salt from the given object.

\(eql T) -- A random salt
INTEGER -- A salt of this size
STRING  -- Use this string as an octet-vector
VECTOR  -- Use this vector directly

See TO-OCTETS")
  
  (pbkdf2-key
   "Hashes PASSWORD with SALT using the PBKDF2 method and the provided DIGEST, repeating the process ITERATION times.

The default DIGEST is SHA512, and the iteration is 1000.

Four values are returned: hash as an octet-vector, salt (as a string), digest, and iterations.

LEGACY. Use PBKDF2-HASH instead.")

  (pbkdf2-hash
   "Hasehs PASSWORD with SALT using the PBKDF2 method and the provided DIGEST, repeating the process ITERATION times.
The returned hash is encoded using the method specified in TO.

The default DIGEST is SHA512, the iteration is 1000, and TO is HEX.

Four values are returned: hash, salt (as a string), digest, and iterations.

See TO.")

  (simple-hash
   "Hashes PASSWORD with SALT using DIGEST as the digest-method and repeats the hashing ITERATIONS times.
The returned hash is encoded using the method specified in TO.

The default DIGEST is SHA512, the iteration is 1000, and TO is HEX.

Four values are returned: hash, salt (as a string), digest, and iterations.

See TO."))
