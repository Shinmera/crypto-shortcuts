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
