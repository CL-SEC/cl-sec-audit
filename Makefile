.PHONY: all clean

all: cl-sec-audit

cl-sec-audit: *.lisp *.asd
	sbcl --eval "(require 'asdf)" \
	     --eval "(asdf:initialize-source-registry (list :source-registry :inherit-configuration (list :directory (uiop:getcwd))))" \
	     --eval "(asdf:make :cl-sec-audit)" --quit

clean:
	rm -f cl-sec-audit
