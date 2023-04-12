#|
 This file is a part of Crypto-Shortcuts
 (c) 2013 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.crypto-shortcuts)

(defgeneric to-octets (string &optional format)
  (:method ((symbol symbol) &optional (format :utf-8))
    (to-octets (string symbol) format))
  (:method ((string string) &optional (format :utf-8))
    (flexi-streams:string-to-octets string :external-format format))
  (:method ((vector vector) &optional format)
    (declare (ignore format)) vector))

(defgeneric to-string (octets &optional format)
  (:method ((vector vector) &optional (format :utf-8))
    (flexi-streams:octets-to-string vector :external-format format))
  (:method ((string string) &optional format)
    (declare (ignore format)) string))

(defgeneric to-hex (vector)
  (:method ((symbol symbol))
    (to-hex (string symbol)))
  (:method ((string string))
    (to-hex (to-octets string)))
  (:method ((vector vector))
    (ironclad:byte-array-to-hex-string vector)))

(defgeneric from-hex (hex-string)
  (:method ((string string))
    (ironclad:hex-string-to-byte-array string)))

(defgeneric to-base64 (sequence)
  (:method ((integer integer))
    (base64:integer-to-base64-string integer))
  (:method ((vector vector))
    (base64:usb8-array-to-base64-string vector))
  (:method ((string string))
    (to-base64 (to-octets string)))
  (:method ((symbol symbol))
    (to-base64 (string symbol))))

(defgeneric from-base64 (vector &optional to)
  (:method ((string string) &optional (to :string))
    (to to (base64:base64-string-to-usb8-array string)))
  (:method ((vector vector) &optional (to :string))
    (from-base64 (to-string vector) to)))

(defgeneric to-base32 (sequence)
  (:method ((vector vector))
    (cl-base32:bytes-to-base32 vector))
  (:method ((string string))
    (to-base32 (to-octets string)))
  (:method ((symbol symbol))
    (to-base32 (string symbol))))

(defgeneric from-base32 (vector &optional to)
  (:method ((string string) &optional (to :string))
    (let ((width (mod (length string) 8)))
      (when (/= width 0)
        (setf string (format NIL "~a~v{=~}" string (- 8 width) 0))))
    (to to (base32:base32-to-bytes string)))
  (:method ((vector vector) &optional (to :string))
    (from-base32 (to-string vector) to)))

(defgeneric to (thing vector)
  (:method ((thing (eql NIL)) vector)
    vector)
  (:method ((thing (eql :octets)) vector)
    (to-octets vector))
  (:method ((thing (eql :string)) vector)
    (to-string vector))
  (:method ((thing (eql :hex)) vector)
    (to-hex vector))
  (:method ((thing (eql :base64)) vector)
    (to-base64 vector))
  (:method ((thing (eql :base32)) vector)
    (to-base32 vector)))

(defgeneric code (from to vector)
  (:method ((from (eql NIL)) to vector)
    (to to vector))
  
  (:method ((from (eql :octets)) (to (eql :octets)) vector)
    vector)
  (:method ((from (eql :octets)) (to (eql :string)) vector)
    (to-string vector))
  (:method ((from (eql :octets)) (to (eql :hex)) vector)
    (to-hex vector))
  (:method ((from (eql :octets)) (to (eql :base64)) vector)
    (to-base64 vector))
  (:method ((from (eql :octets)) (to (eql :base32)) vector)
    (to-base32 vector))
  
  (:method ((from (eql :string)) (to (eql :octets)) vector)
    (to-octets vector))
  (:method ((from (eql :string)) (to (eql :string)) vector)
    vector)
  (:method ((from (eql :string)) (to (eql :hex)) vector)
    (to-hex vector))
  (:method ((from (eql :string)) (to (eql :base64)) vector)
    (to-base64 vector))
  (:method ((from (eql :string)) (to (eql :base32)) vector)
    (to-base32 vector))
  
  (:method ((from (eql :hex)) (to (eql :octets)) vector)
    (from-hex vector))
  (:method ((from (eql :hex)) (to (eql :string)) vector)
    (to-string (from-hex vector)))
  (:method ((from (eql :hex)) (to (eql :hex)) vector)
    vector)
  (:method ((from (eql :hex)) (to (eql :base64)) vector)
    (to-base64 (from-hex vector)))
  (:method ((from (eql :hex)) (to (eql :base32)) vector)
    (to-base32 (from-hex vector)))
  
  (:method ((from (eql :base64)) to vector)
    (from-base64 vector to))
  (:method ((from (eql :base32)) to vector)
    (from-base32 vector to)))
