#|
 This file is a part of Crypto-Shortcuts
 (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.crypto-shortcuts)

(defun totp (secret &key (time (get-universal-time)) (digest :sha1) (period 30) (digits 6))
  (let ((stamp (truncate (- time (encode-universal-time 0 0 0 1 1 1970 0)) period))
        (octets (make-array 8 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below 8
          for j downfrom (- 64 8) by 8
          do (setf (aref octets i) (ldb (byte 8 j) stamp)))
    (let* ((hmac (hmac octets secret :digest digest :to :octets))
           (offset (logand (aref hmac (1- (length hmac))) #xF))
           (code (logior (ash (logand #x7F (aref hmac (+ offset 0))) 24)
                         (ash (logand #xFF (aref hmac (+ offset 1))) 16)
                         (ash (logand #xFF (aref hmac (+ offset 2)))  8)
                         (ash (logand #xFF (aref hmac (+ offset 3)))  0))))
      (mod (logand code #x7FFFFFFF) (expt 10 digits)))))

(defun url-encode (thing)
  (when thing
    (with-output-to-string (out)
      (loop for octet across (to-octets thing)
            for char = (code-char octet)
            do (cond ((or (char<= #\0 char #\9)
                          (char<= #\a char #\z)
                          (char<= #\A char #\Z)
                          (find char "-._~" :test #'char=))
                      (write-char char out))
                     (t (format out "%~2,'0x" (char-code char))))))))

(defun totp-uri (account &key (secret (make-salt 10)) issuer (digest :sha1) (period 30) (digits 6))
  (values (format NIL "otpauth://totp/~@[~a:~]~a?secret=~a~@[&issuer=~a~]~@[&algorithm=~a~]~@[&period=~a~]~@[&digits=~a~]"
                  (url-encode issuer) (url-encode account) (url-encode (string-right-trim "=" (to-base32 secret))) (url-encode issuer) digest period digits)
          secret))
