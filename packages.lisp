(defpackage #:cl-sec-audit
  (:use #:cl)
  (:export #:audit
           #:audit-system
           #:update-advisory-database
           #:*advisory-directory*
           #:*advisory-url*
           #:*advisory-cache-directory*
           #:*severity-threshold*
           #:enumerate-ocicl-systems
           #:enumerate-loaded-systems
           #:advisory
           #:advisory-id
           #:advisory-title
           #:advisory-severity
           #:advisory-cvss-score
           #:advisory-project-name
           #:advisory-systems
           #:advisory-introduced-in
           #:advisory-fixed-in
           #:advisory-affected-dists
           #:advisory-description
           #:advisory-recommendation
           #:finding
           #:finding-advisory
           #:finding-system-name
           #:finding-installed-version
           #:finding-dist-type
           #:main))
