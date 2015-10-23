#|
  This file is a part of Crypto-Shortcuts
  (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
  Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.crypto-shortcuts)

(defgeneric normalize-key (method key)
  (:method ((method (eql :hash)) key)
    (sha256 key :to :octets))
  (:method ((method (eql :fit)) key)
    (to-octets
     (cond ((< (length key) 32)
            (concatenate 'string key (make-string (- 32 (length key)) :initial-element #\-)))
           ((< 32 (length key))
            (subseq key 0 32))
           (T key))))
  (:method ((method (eql NIL)) key)
    (to-octets key)))

(defgeneric get-cipher (key &key cipher mode IV)
  (:method (key &key (cipher :aes) mode IV)
    (ironclad:make-cipher cipher :key (to-octets key) :mode mode :initialization-vector IV)))

(defgeneric encrypt (text key &key cipher mode IV to normalize-key)
  (:method (text key &key (cipher :aes) (mode :ecb) (IV (ironclad:make-random-salt)) (to :base64) normalize-key)
    (let* ((key (normalize-key normalize-key key))
           (text (to-octets (to-base64 text)))
           (cipher (get-cipher key :cipher cipher :mode mode :IV IV)))
      (ironclad:encrypt-in-place cipher text)
      (values (to to text) key cipher mode IV))))

(defgeneric decrypt (text key &key cipher mode IV from normalize-key)
  (:method (text key &key (cipher :aes) (mode :ecb) IV (from :base64) normalize-key)
    (let* ((text (code from :octets text))
           (key (normalize-key normalize-key key))
           (cipher (get-cipher key :cipher cipher :mode mode :IV IV)))
      (ironclad:decrypt-in-place cipher text)
      (values (from-base64 text) key cipher mode IV))))

(defgeneric hmac (text key &key digest to)
  (:method (text key &key (digest :sha512) (to :base64))
    (let* ((key (to-octets key)) (text (to-octets text))
           (hmac (ironclad:make-hmac key digest)))
      (ironclad:update-hmac hmac text)
      (values (to to (ironclad:hmac-digest hmac)) key digest))))

(defgeneric cmac (text key &key cipher mode iv to normalize-key)
  (:method (text key &key (cipher :aes) (mode :ecb) iv (to :base64) normalize-key)
    (let ((text (to-octets text))
          (key (normalize-key normalize-key key))
          (cmac (ironclad:make-cmac key (get-cipher key :cipher cipher :mode mode :iv iv))))
      (ironclad:update-cmac cmac text)
      (values (to to (ironclad:cmac-digest cmac)) key cipher mode iv))))
