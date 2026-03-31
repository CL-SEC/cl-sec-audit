(in-package #:cl-sec-audit)

;;; Match installed systems against CL-SEC advisories.

(defstruct finding
  advisory         ; the ADVISORY struct
  system-name      ; installed system name
  installed-version ; version/tag/hash of installed system
  dist-type)       ; :quicklisp, :ocicl, :git

(defun version<= (a b)
  "Compare two version strings. Handles YYYYMMDD-hash, YYYY-MM-DD, and semver.
Returns T if A <= B, NIL otherwise. Returns T if comparison is indeterminate."
  (cond
    ;; If either is nil, we can't compare -- assume affected
    ((or (null a) (null b)) t)
    ;; Same string
    ((string= a b) t)
    ;; Both look like dates YYYY-MM-DD (quicklisp format)
    ((and (= (length a) 10) (= (length b) 10)
          (char= (char a 4) #\-) (char= (char b 4) #\-))
     (string<= a b))
    ;; Both look like YYYYMMDD-hash (ocicl format)
    ((and (> (length a) 8) (> (length b) 8)
          (every #'digit-char-p (subseq a 0 (min 8 (length a))))
          (every #'digit-char-p (subseq b 0 (min 8 (length b)))))
     (string<= (subseq a 0 8) (subseq b 0 8)))
    ;; Can't determine ordering -- assume affected
    (t t)))

(defun system-matches-advisory-p (installed advisory)
  "Check if an INSTALLED-SYSTEM is affected by an ADVISORY."
  (let ((sys-name (installed-system-name installed))
        (adv-systems (advisory-systems advisory))
        (adv-project (advisory-project-name advisory)))
    ;; Check if the system name matches either the project name or a listed system
    (unless (or (and adv-project
                     (string-equal sys-name adv-project))
                (member sys-name adv-systems :test #'string-equal))
      (return-from system-matches-advisory-p nil))

    ;; If there's a source-level fix, check git hash
    (when (and (advisory-fixed-in advisory)
               (eq (installed-system-dist-type installed) :git))
      (let ((installed-hash (installed-system-dist-version installed))
            (fix-hash (advisory-fixed-in advisory)))
        ;; If the installed hash matches or starts with the fix hash, it's fixed
        (when (and installed-hash fix-hash
                   (or (string= installed-hash fix-hash)
                       (starts-with-p fix-hash installed-hash)
                       (starts-with-p installed-hash fix-hash)))
          (return-from system-matches-advisory-p nil))))

    ;; Check dist-specific matching
    (let ((dist-type (installed-system-dist-type installed))
          (dist-version (installed-system-dist-version installed)))
      (cond
        ;; Quicklisp: match against quicklisp dist entries
        ((eq dist-type :quicklisp)
         (let ((ql-entry (find "quicklisp" (advisory-affected-dists advisory)
                               :key #'dist-entry-dist :test #'string-equal)))
           (if ql-entry
               (and (or (null (dist-entry-first-affected ql-entry))
                        (version<= (dist-entry-first-affected ql-entry) dist-version))
                    (or (null (dist-entry-fixed-in ql-entry))
                        (not (version<= (dist-entry-fixed-in ql-entry) dist-version))))
               ;; No quicklisp entry in advisory -- check if there are ANY dist entries
               ;; If none, the advisory applies to all installations
               (null (advisory-affected-dists advisory)))))

        ;; ocicl: match against ocicl dist entries
        ((eq dist-type :ocicl)
         (let ((ocicl-entry (find "ocicl" (advisory-affected-dists advisory)
                                  :key #'dist-entry-dist :test #'string-equal)))
           (if ocicl-entry
               (and (or (null (dist-entry-first-affected ocicl-entry))
                        (version<= (dist-entry-first-affected ocicl-entry) dist-version))
                    (or (null (dist-entry-fixed-in ocicl-entry))
                        (not (version<= (dist-entry-fixed-in ocicl-entry) dist-version))))
               (null (advisory-affected-dists advisory)))))

        ;; Git: match on commit hash if possible
        ((eq dist-type :git)
         ;; For git, if we can't determine the exact version, assume affected
         ;; unless there's a fixed-in and it matches
         t)

        ;; Unknown: assume affected
        (t t)))))

(defun find-matching-advisories (installed-system advisories)
  "Return a list of FINDING structs for all advisories affecting INSTALLED-SYSTEM."
  (let ((findings nil))
    (dolist (adv advisories)
      (when (system-matches-advisory-p installed-system adv)
        (push (make-finding
               :advisory adv
               :system-name (installed-system-name installed-system)
               :installed-version (installed-system-dist-version installed-system)
               :dist-type (installed-system-dist-type installed-system))
              findings)))
    (nreverse findings)))
