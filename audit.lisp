(in-package #:cl-sec-audit)

;;; Main audit entry points and reporting.

(defvar *advisory-url*
  "https://cl-sec.github.io/cl-sec-advisories/advisories.tar.gz"
  "URL to download the CL-SEC advisory database tarball.")

(defvar *advisory-cache-directory*
  (merge-pathnames ".cache/cl-sec-audit/"
                   (user-homedir-pathname))
  "Local cache directory for downloaded advisory YAML files.")

(defvar *advisory-directory* nil
  "Directory containing CL-SEC advisory YAML files.
NIL means auto-download from *advisory-url* on first use.
Set to a pathname to use a local checkout instead.")

(defvar *severity-threshold* nil
  "When set to a string (e.g. \"high\"), only report findings at or above
this severity level. NIL means report everything.")

;;; --- Advisory database download and caching ---

(defun download-to-file (url path)
  "Download URL to PATH using curl. Returns PATH on success, NIL on failure."
  (ensure-directories-exist path)
  (handler-case
      (let ((exit-code (nth-value 2
                         (uiop:run-program
                          (list "curl" "-sL" "-o" (namestring path) url)
                          :output nil :error-output nil))))
        (when (zerop exit-code)
          path))
    (error () nil)))

(defun extract-tarball (tarball-path output-dir)
  "Extract a .tar.gz file to OUTPUT-DIR. Returns OUTPUT-DIR on success."
  (ensure-directories-exist output-dir)
  (handler-case
      (let ((exit-code (nth-value 2
                         (uiop:run-program
                          (list "tar" "xzf" (namestring tarball-path)
                                "-C" (namestring output-dir))
                          :output nil :error-output nil))))
        (when (zerop exit-code)
          output-dir))
    (error () nil)))

(defun update-advisory-database (&key (url *advisory-url*)
                                   (cache-dir *advisory-cache-directory*)
                                   (stream *error-output*))
  "Download the latest CL-SEC advisory database and cache it locally.
Returns the cache directory path on success, NIL on failure."
  (let ((tmp-tarball (merge-pathnames
                      (format nil "cl-sec-advisories-~A.tar.gz"
                              (get-universal-time))
                      (uiop:temporary-directory))))
    (format stream "~&Downloading CL-SEC advisory database...~%")
    (unwind-protect
         (when (download-to-file url tmp-tarball)
           ;; Clear old cache
           (when (probe-file cache-dir)
             (uiop:delete-directory-tree cache-dir
                                         :validate t
                                         :if-does-not-exist :ignore))
           (when (extract-tarball tmp-tarball cache-dir)
             (let ((count (length (uiop:directory-files cache-dir "*.yaml"))))
               (format stream "~&Cached ~D advisories in ~A~%" count cache-dir)
               ;; Update *advisory-directory* to use the fresh cache
               (setf *advisory-directory* cache-dir)
               cache-dir)))
      ;; Clean up temp file
      (when (probe-file tmp-tarball)
        (delete-file tmp-tarball)))))

;;; --- Reporting ---

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

;;; --- Scanning ---

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

(defun ensure-advisory-database (&key (stream *error-output*))
  "Ensure the advisory database is available, downloading if needed.
Returns the advisory directory path."
  (cond
    ;; Already have a directory with files
    ((and *advisory-directory*
          (probe-file *advisory-directory*)
          (uiop:directory-files *advisory-directory* "*.yaml"))
     *advisory-directory*)
    ;; Try downloading
    (t
     (format stream "~&No local advisory database found. Downloading...~%")
     (or (update-advisory-database :stream stream)
         (error "Failed to download CL-SEC advisory database from ~A"
                *advisory-url*)))))

(defun audit (&key (directory nil directory-supplied-p)
                (project-directory nil)
                (severity *severity-threshold*)
                (update nil)
                (stream *standard-output*))
  "Scan systems for known CL-SEC vulnerabilities.

If PROJECT-DIRECTORY is given, scan the ocicl.csv in that directory
without requiring systems to be loaded into ASDF.  This is the
recommended way to audit a project:

  (cl-sec-audit:audit :project-directory #p\"~/git/icl/\")

If PROJECT-DIRECTORY is NIL, fall back to scanning all loaded ASDF
systems (works with Quicklisp, ocicl, and git checkouts).

DIRECTORY overrides the advisory database location.
UPDATE if T, download the latest database before scanning.
SEVERITY filters: \"critical\", \"high\", \"medium\", or NIL for all.
Returns a list of FINDING structs."
  ;; Update database if requested
  (when update
    (update-advisory-database :stream stream))
  ;; Resolve advisory directory
  (let ((dir (if directory-supplied-p
                 directory
                 (ensure-advisory-database :stream stream))))
    (format stream "Loading CL-SEC advisory database from ~A...~%" dir)
    (let ((advisories (load-advisory-database dir)))
      (format stream "Loaded ~D advisories.~%" (length advisories))
      (cond
        ;; Mode 1: Scan an ocicl project directory
        (project-directory
         (let ((pdir (uiop:ensure-directory-pathname project-directory)))
           (multiple-value-bind (installed csv-path)
               (enumerate-ocicl-systems pdir)
             (cond
               (installed
                (format stream "Found ocicl.csv at ~A~%" csv-path)
                (format stream "Scanning ~D systems...~%~%" (length installed))
                (run-scan installed advisories severity stream))
               (t
                (format stream "No ocicl.csv found. Checking git...~%")
                (let ((hash (git-short-hash pdir)))
                  (if hash
                      (progn
                        (format stream "Git checkout at ~A~%~%" hash)
                        (let ((systems (enumerate-git-project pdir hash)))
                          (format stream "Found ~D system~:P.~%~%" (length systems))
                          (run-scan systems advisories severity stream)))
                      (progn
                        (format stream "No ocicl.csv or git repo found in ~A~%" pdir)
                        nil))))))))

        ;; Mode 2: Scan loaded ASDF systems
        (t
         (format stream "Scanning loaded ASDF systems...~%~%")
         (run-scan (enumerate-loaded-systems) advisories severity stream))))))

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

(defun audit-system (system-name &key (directory nil directory-supplied-p))
  "Check a single system against the CL-SEC advisory database.
Returns a list of FINDING structs."
  (let* ((dir (if directory-supplied-p
                  directory
                  (ensure-advisory-database)))
         (advisories (load-advisory-database dir))
         (sys-info (detect-system-info system-name)))
    (if sys-info
        (find-matching-advisories sys-info advisories)
        (progn
          (warn "System ~A is not loaded or not found." system-name)
          nil))))
