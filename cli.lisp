(in-package #:cl-sec-audit)

;;; Command-line interface for standalone executable use.

(defun print-usage ()
  (format *error-output* "Usage: cl-sec-audit [OPTIONS] [PROJECT-DIRECTORY]~%~%")
  (format *error-output* "Scan Common Lisp projects for known CL-SEC vulnerabilities.~%~%")
  (format *error-output* "Options:~%")
  (format *error-output* "  --advisories DIR   Path to advisories directory~%")
  (format *error-output* "  --severity LEVEL   Minimum severity: critical, high, medium, low~%")
  (format *error-output* "  --help             Show this help message~%"))

(defun parse-args (args)
  "Parse command-line ARGS. Returns (values project-dir advisories-dir severity)."
  (let (project-dir advisories-dir severity)
    (loop while args do
      (let ((arg (pop args)))
        (cond
          ((string= arg "--help")
           (print-usage)
           (uiop:quit 0))
          ((string= arg "--advisories")
           (setf advisories-dir (pop args))
           (unless advisories-dir
             (format *error-output* "Error: --advisories requires a directory argument~%")
             (uiop:quit 1)))
          ((string= arg "--severity")
           (setf severity (pop args))
           (unless severity
             (format *error-output* "Error: --severity requires an argument~%")
             (uiop:quit 1)))
          ((string= arg "--end-runtime-options") nil)
          ((and (> (length arg) 0) (char= (char arg 0) #\-))
           (format *error-output* "Unknown option: ~A~%" arg)
           (print-usage)
           (uiop:quit 1))
          (t
           (setf project-dir arg)))))
    (values project-dir advisories-dir severity)))

(defun main ()
  "Entry point for the standalone executable."
  (handler-case
      (let ((args (uiop:command-line-arguments)))
        (multiple-value-bind (project-dir advisories-dir severity)
            (parse-args args)
          (let ((findings (audit
                           :project-directory (or project-dir (uiop:getcwd))
                           :directory (if advisories-dir
                                         (uiop:ensure-directory-pathname advisories-dir)
                                         *advisory-directory*)
                           :severity severity)))
            (uiop:quit (if (and findings (> (length findings) 0)) 1 0)))))
    (error (e)
      (format *error-output* "Error: ~A~%" e)
      (uiop:quit 2))))
