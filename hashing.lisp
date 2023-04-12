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
            salt
            digest iterations)))

(defun simple-hash (password salt &key (digest :sha512) (iterations 1000) (to :hex))
  (let ((salt (make-salt salt))
        (hash (ironclad:make-digest digest)))
    (ironclad:update-digest hash salt)
    (ironclad:update-digest hash (to-octets (to-base64 password)))
    (dotimes (x iterations)
      (ironclad:update-digest hash (ironclad:produce-digest hash)))
    (values (to to (ironclad:produce-digest hash))
            (to-string salt)
            digest iterations)))

(defun %rfc-2307-hash (digest password salt iterations)
  (flet ((digest (thing)
           (let ((digest (ironclad:make-digest digest)))
             (ironclad:update-digest digest thing)
             (dotimes (x (1- iterations))
               (ironclad:update-digest digest (ironclad:produce-digest digest)))
             (ironclad:produce-digest digest))))
    (if salt
        (concatenate '(vector (unsigned-byte 8)) (digest (concatenate '(vector (unsigned-byte 8)) (to-octets password) salt)) salt)
        (digest (to-octets password)))))

(defun rfc-2307-hash (password &key (method :sha512) salt (iterations 1000))
  (when salt (setf salt (make-salt salt)))
  (values
   (flet ((hash (digest)
            (to-base64 (%rfc-2307-hash digest password salt iterations))))
     (cond ((eql :sha method)
            (format NIL "{~:[~;s~]sha~[~;~:;,~:*~a~]}~a" salt iterations (hash :sha1)))
           ((eql :pbkdf2 method)
            (multiple-value-bind (hash salt digest iterations) (pbkdf2-hash password (or salt T) :iterations iterations :to :octets)
              (format NIL "{pbkdf2,~(~a~),~a}~a" digest iterations (to-base64 (concatenate '(vector (unsigned-byte 8)) hash salt)))))
           ((find method (ironclad:list-all-digests))
            (format NIL "{~:[~;s~]~(~a~)~[~;~:;,~:*~a~]}~a" salt method iterations (hash method)))
           ((char-equal #\s (char (string method) 0))
            (setf salt (make-salt T))
            (rfc-2307-hash password :method (intern (subseq (string method) 1) "KEYWORD") :salt salt :iterations iterations))
           (T
            (error "Unknown method ~s" method))))
   salt))

(defun split (split string)
  (let ((items ()) (out (make-string-output-stream)))
    (flet ((push-item ()
             (let ((string (get-output-stream-string out)))
               (when (string/= "" string)
                 (push string items)))))
      (loop for char across string
            do (if (char= char split)
                   (push-item)
                   (write-char char out))
            finally (push-item))
      (nreverse items))))

(defun check-rfc-2307-hash (password hash)
  (let ((start (position #\{ hash))
        (end (position #\} hash)))
    (unless (and start end (< (1+ start) end))
      (error "Bad hash: ~s" hash))
    (destructuring-bind (method . args) (split #\, (subseq hash (1+ start) end))
      (flet ((check (digest salted iterations)
               (let* ((octets (base64:base64-string-to-usb8-array (subseq hash (1+ end))))
                      (generated (%rfc-2307-hash digest password (when salted (subseq octets (ironclad:digest-length digest))) iterations)))
                 (and (= (length octets) (length generated))
                      (every #'= octets generated)))))
        (cond ((string-equal method "sha")
               (destructuring-bind (&optional (iterations "1")) args
                 (check :sha1 NIL (parse-integer iterations))))
              ((string-equal method "ssha")
               (destructuring-bind (&optional (iterations "1")) args
                 (check :sha1 T (parse-integer iterations))))
              ((string-equal method "pbkdf2" :end1 (length "pbkdf2"))
               (destructuring-bind (&optional (digest "sha512") (iterations "1000")) args
                 (let* ((digest (find-digest digest))
                        (octets (base64:base64-string-to-usb8-array (subseq hash (1+ end))))
                        (generated (pbkdf2-hash password (subseq octets (ironclad:digest-length digest))
                                                :digest digest
                                                :iterations (parse-integer iterations)
                                                :to :octets)))
                   (loop for i from 0 below (length generated)
                         always (= (aref generated i) (aref octets i))))))
              ((find method (ironclad:list-all-digests) :test #'string-equal)
               (destructuring-bind (&optional (iterations "1")) args
                 (check (find method (ironclad:list-all-digests) :test #'string-equal) NIL (parse-integer iterations))))
              ((char-equal #\s (char method 0))
               (let ((digest (find-digest (subseq method 1))))
                 (if digest
                     (destructuring-bind (&optional (iterations "1")) args
                       (check digest T (parse-integer iterations)))
                     (error "Unknown method ~s" method))))
              (T
               (error "Unknown method ~s" method)))))))
