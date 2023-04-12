#|
 This file is a part of Crypto-Shortcuts
 (c) 2014 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(asdf:defsystem crypto-shortcuts
  :license "zlib"
  :author "Nicolas Hafner <shinmera@tymoon.eu>"
  :maintainer "Nicolas Hafner <shinmera@tymoon.eu>"
  :description "Shorthand functions for common cryptography tasks such as hashing, encrypting, and encoding."
  :homepage "https://Shinmera.github.io/crypto-shortcuts/"
  :bug-tracker "https://github.com/Shinmera/crypto-shortcuts/issues"
  :source-control (:git "https://github.com/Shinmera/crypto-shortcuts.git")
  :version "2.0.0"
  :serial T
  :components ((:file "package")
               (:file "encode")
               (:file "crypto")
               (:file "hashing")
               (:file "digests")
               (:file "documentation"))
  :depends-on (:ironclad :cl-base64 :cl-base32 :flexi-streams))
