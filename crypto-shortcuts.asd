#|
 This file is a part of Crypto-Shortcuts
 (c) 2014 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:cl-user)
(asdf:defsystem crypto-shortcuts
  :license "Artistic"
  :author "Nicolas Hafner <shinmera@tymoon.eu>"
  :maintainer "Nicolas Hafner <shinmera@tymoon.eu>"
  :description "Shorthand functions for common cryptography tasks such as hashing, encrypting, and encoding."
  :homepage "https://github.com/Shinmera/crypto-shortcuts"
  :version "2.0.0"
  :serial T
  :components ((:file "package")
               (:file "encode")
               (:file "crypto")
               (:file "hashing")
               (:file "digests")
               (:file "documentation"))
  :depends-on (:ironclad :cl-base64 :flexi-streams))
