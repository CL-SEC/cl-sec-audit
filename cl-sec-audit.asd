(defsystem "cl-sec-audit"
  :version "0.1.0"
  :author "CLSEC Contributors"
  :license "Apache-2.0"
  :description "Scan installed Common Lisp systems for known CLSEC vulnerabilities."
  :depends-on ("uiop")
  :build-operation "program-op"
  :build-pathname "cl-sec-audit"
  :entry-point "cl-sec-audit:main"
  :serial t
  :components ((:file "packages")
               (:file "advisory-parser")
               (:file "version-detect")
               (:file "matcher")
               (:file "audit")
               (:file "cli")))

#+sb-core-compression
(defmethod asdf:perform ((o asdf:image-op) (c asdf:system))
  (uiop:dump-image (asdf:output-file o c) :executable t :compression t))
