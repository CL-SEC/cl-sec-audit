(in-package #:cl-sec-audit)

;;; Main audit entry points and reporting.

(defvar *advisory-directory*
  (or
   ;; Look for cl-sec-advisories as a sibling checkout
   (let ((sibling (merge-pathnames "../cl-sec-advisories/advisories/"
                                   (asdf:system-source-directory "cl-sec-audit"))))
     (when (probe-file sibling) sibling))
   ;; Fall back to advisories/ in the same directory (embedded use)
   (merge-pathnames "advisories/"
                    (asdf:system-source-directory "cl-sec-audit")))
  "Directory containing CL-SEC advisory YAML files.
Set this to the path of your cl-sec-advisories/advisories/ checkout.
Auto-detected from sibling directory ../cl-sec-advisories/advisories/.")

(defvar *severity-threshold* nil
  "When set to a string (e.g. \"high\"), only report findings at or above
this severity level. NIL means report everything.")

(defun severity-rank (severity)
  "Return a numeric rank for a severity string. Higher = more severe."
  (cond
    ((string-equal severity "critical") 4)
    ((string-equal severity "high") 3)
    ((string-equal severity "medium") 2)
    ((string-equal severity "low") 1)
    (t 0)))

(defun finding-above-threshold-p (finding)
  "Check if FINDING meets the severity threshold."
  (or (null *severity-threshold*)
      (>= (severity-rank (advisory-severity (finding-advisory finding)))
          (severity-rank *severity-threshold*))))

(defun format-severity (severity)
  "Format severity string with consistent width."
  (format nil "~6A" (string-upcase severity)))

(defun print-finding (finding &optional (stream *standard-output*))
  "Print a single finding in human-readable format."
  (let* ((adv (finding-advisory finding))
         (id (advisory-id adv))
         (title (advisory-title adv))
         (severity (advisory-severity adv))
         (score (advisory-cvss-score adv))
         (sys-name (finding-system-name finding))
         (version (finding-installed-version finding))
         (dist (finding-dist-type finding)))
    (format stream "~A [~A~@[ ~,1F~]] ~A~%"
            id (format-severity severity) score title)
    (format stream "  System: ~A  Version: ~A (~A)~%"
            sys-name (or version "unknown") dist)
    (when (advisory-fixed-in adv)
      (format stream "  Fixed in: ~A~%" (advisory-fixed-in adv)))
    (format stream "~%")))

(defun print-summary (findings &optional (stream *standard-output*))
  "Print a summary of all findings."
  (let ((critical 0) (high 0) (medium 0) (low 0))
    (dolist (f findings)
      (let ((sev (advisory-severity (finding-advisory f))))
        (cond
          ((string-equal sev "critical") (incf critical))
          ((string-equal sev "high") (incf high))
          ((string-equal sev "medium") (incf medium))
          ((string-equal sev "low") (incf low)))))
    (format stream "~%CL-SEC Audit Summary: ~D finding~:P~%"
            (length findings))
    (format stream "  Critical: ~D  High: ~D  Medium: ~D  Low: ~D~%"
            critical high medium low)
    (when (> (+ critical high) 0)
      (format stream "~%  *** ~D critical/high severity issue~:P require attention ***~%"
              (+ critical high)))))

(defun run-scan (installed-systems advisories severity stream)
  "Run the advisory matcher against a list of installed systems.
Returns a sorted list of findings."
  (let ((*severity-threshold* severity)
        (all-findings nil))
    (dolist (sys installed-systems)
      (let ((findings (find-matching-advisories sys advisories)))
        (dolist (f findings)
          (when (finding-above-threshold-p f)
            (push f all-findings)
            (print-finding f stream)))))
    (let ((results (sort (nreverse all-findings) #'>
                         :key (lambda (f)
                                (or (advisory-cvss-score (finding-advisory f)) 0)))))
      (print-summary results stream)
      results)))

(defun audit (&key (directory *advisory-directory*)
                (project-directory nil)
                (severity *severity-threshold*)
                (stream *standard-output*))
  "Scan systems for known CL-SEC vulnerabilities.

If PROJECT-DIRECTORY is given, scan the ocicl.csv in that directory
without requiring systems to be loaded into ASDF.  This is the
recommended way to audit a project:

  (cl-sec-audit:audit :project-directory #p\"~/git/icl/\")

If PROJECT-DIRECTORY is NIL, fall back to scanning all loaded ASDF
systems (works with Quicklisp, ocicl, and git checkouts).

DIRECTORY is the path to the advisories/ directory.
SEVERITY filters results: \"critical\", \"high\", \"medium\", or NIL for all.
Returns a list of FINDING structs."
  (format stream "Loading CL-SEC advisory database from ~A...~%" directory)
  (let ((advisories (load-advisory-database directory)))
    (format stream "Loaded ~D advisories.~%" (length advisories))
    (cond
      ;; Mode 1: Scan an ocicl project directory
      (project-directory
       (let ((dir (uiop:ensure-directory-pathname project-directory)))
         (multiple-value-bind (installed csv-path)
             (enumerate-ocicl-systems dir)
           (cond
             (installed
              (format stream "Found ocicl.csv at ~A~%" csv-path)
              (format stream "Scanning ~D systems...~%~%" (length installed))
              (run-scan installed advisories severity stream))
             (t
              ;; No ocicl.csv -- try git
              (format stream "No ocicl.csv found. Checking git...~%")
              (let ((hash (git-short-hash dir)))
                (if hash
                    (progn
                      (format stream "Git checkout at ~A~%~%" hash)
                      ;; Scan .asd files in the directory
                      (let ((systems (enumerate-git-project dir hash)))
                        (format stream "Found ~D system~:P.~%~%" (length systems))
                        (run-scan systems advisories severity stream)))
                    (progn
                      (format stream "No ocicl.csv or git repo found in ~A~%" dir)
                      nil))))))))

      ;; Mode 2: Scan loaded ASDF systems
      (t
       (format stream "Scanning loaded ASDF systems...~%~%")
       (run-scan (enumerate-loaded-systems) advisories severity stream)))))

(defun enumerate-git-project (directory hash)
  "Find .asd files in DIRECTORY and create installed-system entries for them."
  (let ((systems nil))
    (dolist (asd-file (uiop:directory-files directory "*.asd"))
      (let ((name (pathname-name asd-file)))
        (push (make-installed-system
               :name (string-downcase name)
               :source-dir directory
               :dist-type :git
               :dist-version hash)
              systems)))
    (nreverse systems)))

(defun audit-system (system-name &key (directory *advisory-directory*))
  "Check a single system against the CL-SEC advisory database.
Returns a list of FINDING structs."
  (let ((advisories (load-advisory-database directory))
        (sys-info (detect-system-info system-name)))
    (if sys-info
        (find-matching-advisories sys-info advisories)
        (progn
          (warn "System ~A is not loaded or not found." system-name)
          nil))))
