#|
 This file is a part of Crypto-Shortcuts
 (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.crypto-shortcuts)

(defmacro define-digest-wrapper (digest)
  `(defun ,(intern (string digest)) (string &key (to :hex) encode (iterations 1))
     ,@(if (ironclad:digest-supported-p (find-symbol (string digest) "IRONCLAD"))
           `(,(format NIL "Turn a string into a ~a-hash.

TO is the returned representation
ENCODE is the encoding before hashing
ITERATIONS is the number of times to hash

See TO." digest)
             (let ((digest (ironclad:make-digest ',digest)))
               (ironclad:update-digest digest (to-octets (to encode string)))
               (dotimes (x (1- iterations))
                 (ironclad:update-digest digest (ironclad:produce-digest digest)))
               (to to (ironclad:produce-digest digest))))
           `("Unsupported!"
             (error ,(format NIL "The ~a digest is not supported on your platform!" digest))))))

(macrolet ((define-all-digests ()
             `(progn
                ,@(loop for digest in (ironclad:list-all-digests)
                        collect `(define-digest-wrapper ,digest)))))
  (define-all-digests))
