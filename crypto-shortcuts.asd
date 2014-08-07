#|
 This file is a part of Crypto-Shortcuts
 (c) 2014 TymoonNET/NexT http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:cl-user)
(asdf:defsystem crypto-shortcuts
  :name "Crypto Shortcuts"
  :license "Artistic"
  :author "Nicolas Hafner <shinmera@tymoon.eu>"
  :maintainer "Nicolas Hafner <shinmera@tymoon.eu>"
  :description "Shorthand functions for common cryptography tasks."
  :homepage "https://github.com/Shinmera/crypto-shortcuts"
  :serial T
  :components ((:file "crypto"))
  :depends-on (:ironclad :cl-base64 :flexi-streams))
