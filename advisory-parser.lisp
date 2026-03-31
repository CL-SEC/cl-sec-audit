(in-package #:cl-sec-audit)

;;; Minimal YAML-subset parser for CL-SEC advisory files.

(defstruct advisory
  id title severity cvss-score cwe
  project-name homepage systems
  introduced-in fixed-in
  affected-dists
  description recommendation)

(defstruct dist-entry
  dist first-affected last-affected fixed-in)

(defun trim-quotes (s)
  (if (and (> (length s) 1)
           (char= (char s 0) #\")
           (char= (char s (1- (length s))) #\"))
      (subseq s 1 (1- (length s)))
      s))

(defun yaml-val (s)
  "Parse a simple YAML scalar value."
  (let ((v (string-trim '(#\Space #\Tab) s)))
    (if (or (string= v "null") (string= v "~") (string= v "[]")
            (string= v "{}") (string= v ""))
        nil
        (trim-quotes v))))

(defun starts-with-p (prefix string)
  (and (>= (length string) (length prefix))
       (string= prefix string :end2 (length prefix))))

(defun split-kv (line)
  "Split 'key: value' returning (values key value-string) or NIL."
  (let ((pos (position #\: line)))
    (when (and pos (> pos 0))
      (values (subseq line 0 pos)
              (string-trim '(#\Space #\Tab) (subseq line (1+ pos)))))))

(defun parse-advisory-file (path)
  "Parse a CL-SEC advisory YAML file into an ADVISORY struct."
  (with-open-file (stream path)
    (let ((adv (make-advisory))
          (in-dists nil)
          (in-systems nil)
          (cur-dist nil)
          (systems nil)
          (dists nil))
      (labels ((save-dist ()
               (when cur-dist (push cur-dist dists) (setf cur-dist nil)))
             (read-multiline (stream)
               "Read a YAML | block, return as string."
               (with-output-to-string (out)
                 (loop for line = (read-line stream nil nil)
                       while line
                       for trimmed = (string-trim '(#\Space #\Tab) line)
                       while (or (string= trimmed "")
                                 (> (- (length line)
                                       (length (string-left-trim '(#\Space #\Tab) line)))
                                    1))
                       do (write-string trimmed out)
                          (write-char #\Newline out)))))
        (loop for line = (read-line stream nil nil)
              while line
              do (let* ((stripped (string-trim '(#\Space #\Tab) line))
                        (indent (- (length line)
                                   (length (string-left-trim '(#\Space #\Tab) line)))))
                   ;; Skip blanks and comments
                   (unless (or (string= stripped "") (starts-with-p "#" stripped))
                     (cond
                       ;; Indent 0: top-level
                       ((zerop indent)
                        (setf in-dists nil in-systems nil)
                        (multiple-value-bind (k v) (split-kv stripped)
                          (when k
                            (cond
                              ((string= k "id") (setf (advisory-id adv) (yaml-val v)))
                              ((string= k "title") (setf (advisory-title adv) (yaml-val v)))
                              ((string= k "severity") (setf (advisory-severity adv) (yaml-val v)))
                              ((string= k "cvss-score")
                               (let ((s (yaml-val v)))
                                 (when s (setf (advisory-cvss-score adv)
                                               (let ((*read-eval* nil)) (read-from-string s))))))
                              ((string= k "cwe") (setf (advisory-cwe adv) (yaml-val v)))))))

                       ;; Indent 2: sub-keys
                       ((= indent 2)
                        (multiple-value-bind (k v) (split-kv stripped)
                          (when k
                            (cond
                              ((string= k "name")
                               (unless (advisory-project-name adv)
                                 (setf (advisory-project-name adv) (yaml-val v))))
                              ((string= k "homepage")
                               (setf (advisory-homepage adv) (yaml-val v)))
                              ((string= k "systems")
                               (setf in-systems t in-dists nil))
                              ((string= k "introduced-in")
                               (setf (advisory-introduced-in adv) (yaml-val v)))
                              ((string= k "fixed-in")
                               (unless in-dists
                                 (setf (advisory-fixed-in adv) (yaml-val v))))
                              ((string= k "affected-dists")
                               (setf in-dists t in-systems nil))
                              ((string= k "description")
                               (when (string= v "|")
                                 (setf (advisory-description adv) (read-multiline stream))))
                              ((string= k "recommendation")
                               (when (string= v "|")
                                 (setf (advisory-recommendation adv) (read-multiline stream))))))))

                       ;; Indent 4+: list items
                       ((and (>= indent 4) (starts-with-p "- " stripped))
                        (let ((item (string-trim '(#\Space #\Tab) (subseq stripped 2))))
                          (cond
                            ((starts-with-p "dist:" item)
                             (save-dist)
                             (setf cur-dist
                                   (make-dist-entry
                                    :dist (yaml-val (subseq item (1+ (position #\: item)))))))
                            (in-systems
                             (push (yaml-val item) systems)))))

                       ;; Indent 6+: dist entry fields
                       ((and (>= indent 6) cur-dist)
                        (multiple-value-bind (k v) (split-kv stripped)
                          (when k
                            (cond
                              ((string= k "first-affected")
                               (setf (dist-entry-first-affected cur-dist) (yaml-val v)))
                              ((string= k "last-affected")
                               (setf (dist-entry-last-affected cur-dist) (yaml-val v)))
                              ((string= k "fixed-in")
                               (setf (dist-entry-fixed-in cur-dist) (yaml-val v))))))))))))

      (when cur-dist (push cur-dist dists))
      (setf (advisory-systems adv) (nreverse systems))
      (setf (advisory-affected-dists adv) (nreverse dists))
      adv)))

(defun load-advisory-database (directory)
  "Load all advisory YAML files from DIRECTORY. Returns a list of ADVISORY structs."
  (let ((advisories nil))
    (dolist (path (sort (uiop:directory-files directory "*.yaml")
                        #'string< :key #'namestring))
      (handler-case
          (let ((adv (parse-advisory-file path)))
            (when (advisory-id adv)
              (push adv advisories)))
        (error (e)
          (warn "Failed to parse ~A: ~A" path e))))
    (nreverse advisories)))
