(defsystem "cl-sec-audit"
  :version "0.1.0"
  :author "CLSEC Contributors"
  :license "Apache-2.0"
  :description "Scan installed Common Lisp systems for known CLSEC vulnerabilities."
  :depends-on ("uiop")
  :serial t
  :components ((:file "packages")
               (:file "advisory-parser")
               (:file "version-detect")
               (:file "matcher")
               (:file "audit")))
