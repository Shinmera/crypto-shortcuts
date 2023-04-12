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
      (mod code (expt 10 digits)))))

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

(defun url-decode (string)
  (let ((out (make-array (length string) :element-type '(unsigned-byte 8) :fill-pointer 0)))
    (loop for i from 0 below (length string)
          for char = (aref string i)
          do (case char
               (#\% (vector-push (parse-integer string :start (+ i 1) :end (+ i 3) :radix 16) out)
                (incf i 2))
               (#\+ (vector-push (char-code #\Space) out))
               (T (vector-push (char-code char) out)))
          finally (return (to-string out)))))

(defun totp-uri (account &key (secret (make-salt 10)) issuer (digest :sha1) (period 30) (digits 6))
  (values (format NIL "otpauth://totp/~@[~a:~]~a?secret=~:@(~a~)~@[&issuer=~a~]~@[&algorithm=~(~a~)~]~@[&period=~a~]~@[&digits=~a~]"
                  (url-encode issuer) (url-encode account) (url-encode (string-right-trim "=" (to-base32 secret))) (url-encode issuer) digest period digits)
          secret))

(defun decode-totp-uri (uri)
  (destructuring-bind (path params) (split #\? uri)
    (let ((params (split #\& params))
          secret issuer (digest :sha1) (period 30) (digits 6))
      (destructuring-bind (uri totp id) (split #\/ path)
        (assert (string-equal "otpauth:" uri))
        (assert (string-equal "totp" totp))
        (destructuring-bind (account/issuer &optional account)
            (split #\: (url-decode id))
          (if account
              (setf issuer account/issuer)
              (setf account account/issuer))
          (dolist (param params (list account :secret secret :issuer issuer :digest digest :period period :digits digits))
            (destructuring-bind (key val) (split #\= param)
              (cond ((string-equal key "secret") (setf secret (from-base32 val :octets)))
                    ((string-equal key "issuer") (setf issuer (url-decode val)))
                    ((string-equal key "algorithm") (setf digest (find-digest val)))
                    ((string-equal key "period") (setf period (parse-integer val)))
                    ((string-equal key "digits") (setf digits (parse-integer val)))))))))))
