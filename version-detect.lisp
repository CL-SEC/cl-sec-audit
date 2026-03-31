(in-package #:cl-sec-audit)

;;; Detect installed systems and their version/dist information.
;;; Supports three modes:
;;;   1. Scan an ocicl project directory (reads ocicl.csv directly)
;;;   2. Scan Quicklisp-managed systems (from loaded ASDF image)
;;;   3. Scan git checkouts (reads commit hash)

(defstruct installed-system
  name           ; system name (string, lowercase)
  source-dir     ; pathname to source directory (may be nil for CSV-only scan)
  dist-type      ; :quicklisp, :ocicl, or :git
  dist-version)  ; QL dist date, ocicl tag, or git short hash

;;; --- ocicl project scanning (primary use case) ---

(defun find-ocicl-csv (&optional (directory (uiop:getcwd)))
  "Find ocicl.csv or systems.csv starting from DIRECTORY.
Checks ocicl.csv first (project-local), then systems.csv (ocicl registry)."
  (loop for d = (uiop:ensure-directory-pathname directory)
          then (uiop:pathname-parent-directory-pathname d)
        while (and d (not (equal d (uiop:pathname-parent-directory-pathname d))))
        for ocicl-csv = (merge-pathnames "ocicl.csv" d)
        for systems-csv = (merge-pathnames "systems.csv" d)
        when (probe-file ocicl-csv) return ocicl-csv
        when (probe-file systems-csv) return systems-csv))

(defun extract-version-from-dir-name (dir-name system-name)
  "Extract the version portion from an ocicl directory name.
Given dir-name \"cl-ppcre-20250606-a2ea581\" and system-name \"cl-ppcre\",
returns \"20250606-a2ea581\"."
  (let ((prefix (concatenate 'string system-name "-")))
    (if (and (> (length dir-name) (length prefix))
             (string-equal prefix (subseq dir-name 0 (length prefix))))
        (subseq dir-name (length prefix))
        ;; Fallback: try to find a YYYYMMDD or semver pattern
        (let ((match (position-if #'digit-char-p dir-name)))
          (when match
            ;; Walk backward to find the start of the version
            (loop for i from (1- match) downto 0
                  when (char= (char dir-name i) #\-)
                    return (subseq dir-name (1+ i))))))))

(defun parse-ocicl-csv (csv-path)
  "Parse an ocicl.csv file. Returns a list of INSTALLED-SYSTEM structs.
Each line: system-name, container-image, dir-with-version/system.asd"
  (let ((systems (make-hash-table :test 'equal))
        (csv-dir (uiop:pathname-directory-pathname csv-path)))
    (with-open-file (stream csv-path :if-does-not-exist nil)
      (when stream
        (loop for line = (read-line stream nil nil)
              while line
              when (and (> (length line) 0) (not (char= (char line 0) #\#)))
              do (let* ((parts (uiop:split-string line :separator ","))
                        (name (string-trim '(#\Space #\Tab) (first parts)))
                        (asd-path (string-trim '(#\Space #\Tab) (third parts))))
                   (when (and name (> (length name) 0)
                              asd-path (> (length asd-path) 0))
                     ;; Skip -test, -tests suffixes to avoid duplicates
                     ;; but include the primary system
                     (unless (gethash name systems)
                       (let* ((slash-pos (position #\/ asd-path))
                              (dir-name (if slash-pos
                                            (subseq asd-path 0 slash-pos)
                                            asd-path))
                              (version (extract-version-from-dir-name dir-name name))
                              (source-dir (when slash-pos
                                            (merge-pathnames
                                             (uiop:ensure-directory-pathname
                                              (concatenate 'string "ocicl/" dir-name "/"))
                                             csv-dir))))
                         (setf (gethash name systems)
                               (make-installed-system
                                :name name
                                :source-dir source-dir
                                :dist-type :ocicl
                                :dist-version version)))))))))
    ;; Return as sorted list
    (let ((result nil))
      (maphash (lambda (k v) (declare (ignore k)) (push v result)) systems)
      (sort result #'string< :key #'installed-system-name))))

(defun enumerate-ocicl-systems (&optional (directory (uiop:getcwd)))
  "Enumerate all systems in an ocicl project by reading ocicl.csv.
Does not require systems to be loaded into ASDF."
  (let ((csv (find-ocicl-csv directory)))
    (if csv
        (values (parse-ocicl-csv csv) csv)
        (values nil nil))))

;;; --- Quicklisp detection ---

(defun quicklisp-available-p ()
  "Check if Quicklisp is loaded."
  (find-package "QUICKLISP"))

(defun quicklisp-dist-version ()
  "Return the current Quicklisp dist version (date string), or NIL."
  (when (quicklisp-available-p)
    (let ((fn (find-symbol "DIST-VERSION" "QL-DIST")))
      (when fn
        (let ((dist (funcall (find-symbol "FIND-DIST" "QL-DIST") "quicklisp")))
          (when dist
            (funcall fn dist)))))))

(defun quicklisp-software-dir ()
  "Return the Quicklisp software directory."
  (when (quicklisp-available-p)
    (let ((home (symbol-value (find-symbol "*QUICKLISP-HOME*" "QUICKLISP"))))
      (when home
        (merge-pathnames "dists/quicklisp/software/" home)))))

(defun system-from-quicklisp-p (source-dir)
  "Check if SOURCE-DIR is under the Quicklisp software directory."
  (let ((ql-dir (quicklisp-software-dir)))
    (when (and ql-dir source-dir)
      (uiop:subpathp source-dir ql-dir))))

;;; --- Git detection ---

(defun git-short-hash (directory)
  "Get the short git commit hash for DIRECTORY, or NIL if not a git repo."
  (handler-case
      (let ((output (uiop:run-program
                     (list "git" "-C" (namestring directory)
                           "rev-parse" "--short" "HEAD")
                     :output '(:string :stripped t)
                     :error-output nil
                     :ignore-error-status t)))
        (when (and output (> (length output) 0)
                   (not (find #\Newline output)))
          output))
    (error () nil)))

;;; --- ASDF-based detection (for loaded systems) ---

(defun detect-system-info (system-name)
  "Detect version/dist info for a loaded ASDF system.
Returns an INSTALLED-SYSTEM or NIL."
  (let* ((system (asdf:find-system system-name nil))
         (source-dir (when system
                       (asdf:system-source-directory system))))
    (when (and system source-dir)
      (cond
        ;; Check Quicklisp
        ((system-from-quicklisp-p source-dir)
         (make-installed-system
          :name (string-downcase (string system-name))
          :source-dir source-dir
          :dist-type :quicklisp
          :dist-version (quicklisp-dist-version)))

        ;; Check ocicl (via directory structure)
        ((let ((parent (car (butlast (pathname-directory source-dir)))))
           (and (stringp parent) (search "ocicl" (string-downcase parent))))
         (let* ((csv (find-ocicl-csv))
                (table (when csv (parse-ocicl-csv csv)))
                (name (string-downcase (string system-name)))
                (match (when table
                         (find name table
                               :key #'installed-system-name
                               :test #'string-equal))))
           (or match
               (make-installed-system
                :name name
                :source-dir source-dir
                :dist-type :ocicl
                :dist-version nil))))

        ;; Fall back to git
        (t
         (make-installed-system
          :name (string-downcase (string system-name))
          :source-dir source-dir
          :dist-type :git
          :dist-version (git-short-hash source-dir)))))))

(defun enumerate-loaded-systems ()
  "Return a list of INSTALLED-SYSTEM structs for all loaded ASDF systems."
  (let ((systems nil))
    (asdf:map-systems
     (lambda (system)
       (let ((info (detect-system-info (asdf:component-name system))))
         (when info
           (push info systems)))))
    (sort systems #'string< :key #'installed-system-name)))
