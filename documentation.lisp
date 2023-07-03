(in-package #:org.shirakumo.crypto-shortcuts)

(defmacro setdocs (&body pairs)
  `(progn
     ,@(loop for (var doc) in pairs
             collect (destructuring-bind (var &optional (type 'function))
                         (if (listp var) var (list var))
                       `(setf (documentation ',var ',type) ,doc)))))

;; crypto.lisp
(setdocs
  (normalize-key
   "Normalizes the KEY to an octet-vector using METHOD.
By default, method can be one of:

:HASH  -- Hash it by sha256
:FIT   -- Truncate or pad it out before turning into octets.
NIL    -- Just turn it into an octet-vector.")
  
  (get-cipher
   "Return the corresponding cipher with KEY using MODE and potentially the initialization-vector IV.")

  (encrypt
   "Encrypt TEXT with KEY using the provided CIPHER/MODE/IV.
Depending on the mode, the key should be of length 16, 32, or 64.
The returned encrypted vector is encoded by the format specified in TO.

The default cipher is AES, default mode is ECB, and default TO is BASE64.

Four values are returned: Encrypted&encoded text, key, cipher, mode, and IV.

See TO
See NORMALIZE-KEY")
  
  (decrypt
   "Decrypt TEXT with KEY using the provided CIPHER/MODE/IV.
Depending on the mode, the key should be of length 16, 32, or 64.
The passed text is decoded by the format specified in FROM.

The default cipher is AES, default mode is ECB, and default TO is BASE64.

Four values are returned: Decrypted text, key, cipher, mode, and IV.

See CODE
See NORMALIZE-KEY")

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

See TO
See NORMALIZE-KEY"))

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

  (to-base32
   "Turns a vector into a base32-encoded string.")

  (from-base32
   "Turns a base32-encoded vector into a vector encoded by TO.
See TO.")

  (to
   "Convenience function to call the various encoders.
By default, THING can be one of:

NIL      -- Returns VECTOR
:OCTETS  -- See TO-OCTETS
:STRING  -- See TO-STRING
:HEX     -- See TO-HEX
:BASE64  -- See TO-BASE64
:BASE32  -- See TO-BASE32")

  (code
   "Convenience function to de/encode in one pass.
By default, FROM and TO can both be one of:

:OCTETS :STRING :HEX :BASE64 :BASE32

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

See TO.")

  (rfc-2307-hash
   "Hashes PASSWORD with METHOD according to the scheme defined in RFC2307.

The returned hash will be a string of the format:

  {method}base64hash

If SALT is passed, or the method is a salted one (sDIGEST), then the salt is
returned as a secondary value and included in the hash. The hash is thus
computed as follows, where no salt is an empty salt sequence.

  base64(digest(password+salt)+salt)

An extension is provided to the standard, wherein extra parameters can
be supplied to the hashing mechanism via commas after the method
name. For most hashes this is just the iteration count, which is
omitted if the count is 1. For PBKDF2, this also includes the actual
digest method used.

See CHECK-RFC-2307-HASH")

  (check-rfc-2307-hash
   "Returns T if the PASSWORD matches the HASH encoded in the scheme defined in RFC2307.

See RFC-2307-HASH"))

;; totp.lisp
(setdocs
  (totp
   "Computes a Timed One Time Password for the given secret key.

TIME should be the universal-time for which the OTP is computed.
DIGEST should be the HMAC inner digest used, default being SHA1.
PERIOD should be how long the OTP is valid for in seconds, default
being 30.
DIGITS should be the number of digits for the OTP, default being 6.

Returns the OTP as an integer. If presenting to the user, you should
pad the integer with zeroes to the required number of digits.

The code is computed according to RFC6238

See TOTP-URI")
  
  (totp-uri
   "Computes a URI to exchange the TOTP parameters with an external authenticator app.

You will most likely want to encode the returned URI into a QR code to
let the user scan it with a phone or other app more easily.

The ACCOUNT should be some identifier for the user account this URI is
for. Typically a username or email address.

You should pass the ISSUER argument to identify the service that is
using the TOTP.

If no explicit SECRET is passed, one will be generated for you and
is returned as the secondary value. You MUST store this secret
somewhere and use it to compute the TOTP.

You must pass the exact same parameters as you intend to use for the
TOTP generation, as otherwise the authenticator application will not
generate the same codes as you, and verification will fail.

This URL is according to Google's Authenticator scheme as described in
 https://github.com/google/google-authenticator/wiki/Key-Uri-Format

See TOTP")

  (decode-totp-uri
   "Decodes a TOTP parameter URI

Returns a list of the same argument list structure as TOTP-URI.

This URL is according to Google's Authenticator scheme as described in
 https://github.com/google/google-authenticator/wiki/Key-Uri-Format

See TOTP-URI"))
