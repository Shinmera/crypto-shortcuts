#|
  This file is a part of Crypto-Shortcuts
  (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
  Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.crypto-shortcuts)

(defgeneric get-cipher (key &key cipher mode IV)
  (:method ((key string) &rest args &key cipher mode IV)
    (declare (ignore cipher mode IV))
    (apply #'get-cipher (to-octets key) args))
  (:method ((key vector) &key (cipher :aes) mode IV)
    (ironclad:make-cipher cipher :key key :mode mode :initialization-vector IV)))

(defgeneric encrypt (text key &key cipher mode IV to)
  (:method ((text string) key &rest args &key cipher mode IV to)
    (declare (ignore cipher mode iv to))
    (apply #'encrypt (to-octets text) key args))
  (:method ((text vector) key &key (cipher :aes) (mode :ecb) (IV (ironclad:make-random-salt)) (to :base64))
    (let ((text (to-octets (to-base64 text)))
          (cipher (get-cipher key :cipher cipher :mode mode :IV IV)))
      (ironclad:encrypt-in-place cipher text)
      (values (to to text) key cipher mode IV))))

(defgeneric decrypt (text key &key cipher mode IV from)
  (:method ((text string) key &rest args &key cipher mode IV (from :base64))
    (declare (ignore cipher mode IV))
    (apply #'decrypt (code from :octets text) key args))
  (:method ((text vector) key &key (cipher :aes) (mode :ecb) IV from)
    (declare (ignore from))
    (let ((cipher (get-cipher key :cipher cipher :mode mode :IV IV)))
      (ironclad:decrypt-in-place cipher text)
      (values (from-base64 text) key cipher mode IV))))

(defgeneric hmac (text key &key digest to)
  (:method ((text string) key &rest args &key digest to)
    (declare (ignore digest to))
    (apply #'hmac (to-octets text) key args))
  (:method (text (key string) &rest args &key digest to)
    (declare (ignore digest to))
    (apply #'hmac text (to-octets key) args))
  (:method ((text vector) (key vector) &key (digest :sha512) (to :base64))
    (let ((hmac (ironclad:make-hmac key digest)))
      (ironclad:update-hmac hmac text)
      (values (to to (ironclad:hmac-digest hmac)) key digest))))

(defgeneric cmac (text key &key cipher mode iv to)
  (:method ((text string) key &rest args &key cipher mode iv to)
    (declare (ignore cipher mode iv to))
    (apply #'cmac (to-octets text) key args))
  (:method (text (key string) &rest args &key cipher mode iv to)
    (declare (ignore cipher mode iv to))
    (apply #'cmac text (to-octets key) args))
  (:method ((text vector) (key vector) &key (cipher :aes) (mode :ctr) iv (to :base64))
    (let ((cmac (ironclad:make-cmac key (get-cipher key :cipher cipher :mode mode :iv iv))))
      (ironclad:update-cmac cmac text)
      (values (to to (ironclad:cmac-digest cmac)) key cipher mode iv))))
