#|
 This file is a part of Crypto-Shortcuts
 (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.crypto-shortcuts)

(defgeneric make-salt (salt)
  (:method ((salt (eql T))) (ironclad:make-random-salt))
  (:method ((size integer)) (ironclad:make-random-salt size))
  (:method ((salt string)) (to-octets salt))
  (:method ((salt vector)) salt))

(defun pbkdf2-key (password salt &rest args &key digest iterations)
  (declare (ignore digest iterations))
  (apply #'pbkdf2-hash password salt :to :octets args))

(defun pbkdf2-hash (password salt &key (digest :sha512) (iterations 1000) (to :hex))
  (let* ((salt (make-salt salt))
         (hash (ironclad:pbkdf2-hash-password
                (to-octets (to-base64 password))
                :salt salt :digest digest :iterations iterations)))
    (values (to to hash)
            (to-string salt)
            digest iterations)))

(defun simple-hash  (password salt &key (digest :sha512) (iterations 1000) (to :hex))
  (let ((salt (make-salt salt))
        (hash (ironclad:make-digest digest)))
    (ironclad:update-digest hash salt)
    (ironclad:update-digest hash (to-octets (to-base64 password)))
    (dotimes (x iterations)
      (ironclad:update-digest hash (ironclad:produce-digest hash)))
    (values (to to (ironclad:produce-digest hash))
            (to-string salt)
            digest iterations)))

(defun %rfc-2307-hash (digest password salt)
  (if salt
      (concatenate '(vector (unsigned-byte 8)) (ironclad:digest-sequence digest (concatenate '(vector (unsigned-byte 8)) (to-octets password) salt)) salt)
      (ironclad:digest-sequence digest (to-octets password))))

(defun rfc-2307-hash (password &key (method :sha512) salt)
  (when salt (setf salt (make-salt salt)))
  (values
   (flet ((hash (digest)
            (to-base64 (%rfc-2307-hash digest password salt))))
     (cond ((eql :sha method)
            (format NIL "{~:[~;s~]sha}~a" salt (hash :sha1)))
           ((find method (ironclad:list-all-digests))
            (format NIL "{~:[~;s~]~(~a~)}~a" salt method (hash method)))
           ((char-equal #\s (char (string method) 0))
            (setf salt (make-salt T))
            (rfc-2307-hash password :method (intern (subseq (string method) 1) "KEYWORD") :salt salt))
           (T
            (error "Unknown method ~s" method))))
   salt))

(defun check-rfc-2307-hash (password hash)
  (let ((start (position #\{ hash))
        (end (position #\} hash)))
    (unless (and start end (< (1+ start) end))
      (error "Bad hash: ~s" hash))
    (let ((method (subseq hash (1+ start) end)))
      (flet ((check (digest &optional salted)
               (let* ((octets (base64:base64-string-to-usb8-array (subseq hash (1+ end))))
                      (generated (%rfc-2307-hash digest password (when salted (subseq octets (ironclad:digest-length digest))))))
                 (and (= (length octets) (length generated))
                      (every #'= octets generated)))))
        (cond ((string-equal method "sha")
               (check :sha1))
              ((string-equal method "ssha")
               (check :sha1 T))
              ((find method (ironclad:list-all-digests) :test #'string-equal)
               (check (find method (ironclad:list-all-digests) :test #'string-equal)))
              ((char-equal #\s (char method 0))
               (let ((digest (find (subseq method 1) (ironclad:list-all-digests) :test #'string-equal)))
                 (if digest
                     (check digest T)
                     (error "Unknown method ~s" method))))
              (T
               (error "Unknown method ~s" method)))))))
