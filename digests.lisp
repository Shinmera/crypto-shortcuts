#|
 This file is a part of Crypto-Shortcuts
 (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.crypto-shortcuts)

(defmacro define-digest-wrapper (digest)
  `(defun ,(intern (string digest)) (string &key (to :hex) encode)
     ,@(if (ironclad:digest-supported-p (find-symbol (string digest) "IRONCLAD"))
           `(,(format NIL "Turn a string into a ~a-hash.

TO is the returned representation
ENCODE is the encoding before hashing

See TO." digest)
             (let ((octets (ironclad:digest-sequence
                            ',digest (to-octets (to encode string)))))
               (to to octets)))
           `("Unsupported!"
             (error ,(format NIL "The ~a digest is not supported on your platform!" digest))))))

(macrolet ((define-all-digests ()
             `(progn
                ,@(loop for digest in (ironclad:list-all-digests)
                        collect `(define-digest-wrapper ,digest)))))
  (define-all-digests))
