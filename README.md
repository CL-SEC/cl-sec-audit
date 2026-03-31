# cl-sec-audit

Scan installed Common Lisp systems for known
[CL-SEC](https://github.com/CL-SEC/cl-sec-advisories) vulnerabilities.

## Setup

```lisp
(asdf:load-system "cl-sec-audit")
```

The advisory database is downloaded automatically on first use from
GitHub Pages and cached in `~/.local/share/cl-sec/advisories/`.

## Usage

```lisp
;; Scan an ocicl project directory
(cl-sec-audit:audit :project-directory #p"~/git/my-project/")

;; Scan all loaded ASDF systems
(cl-sec-audit:audit)

;; Only show high/critical findings
(cl-sec-audit:audit :severity "high")

;; Force-update the database before scanning
(cl-sec-audit:audit :update t)

;; Update the database without scanning
(cl-sec-audit:update-advisory-database)

;; Check a single system
(cl-sec-audit:audit-system "ironclad")
```

## How It Works

1. Downloads the advisory database from
   `https://cl-sec.github.io/cl-sec-advisories/advisories.tar.gz`
   (cached locally in `~/.local/share/cl-sec/advisories/`)
2. Enumerates installed systems via ocicl.csv, Quicklisp, or ASDF
3. Extracts version information (ocicl tags, QL dist dates, git hashes)
4. Matches against CL-SEC advisory `affected-dists` entries
5. Reports findings sorted by severity

## Configuration

```lisp
;; Use a local git checkout instead of downloading
(setf cl-sec-audit:*advisory-directory*
      #p"~/git/cl-sec-advisories/advisories/")

;; Change the cache location
(setf cl-sec-audit:*advisory-cache-directory*
      #p"/tmp/cl-sec/advisories/")
```

## Dependencies

Only UIOP (bundled with ASDF). Uses `curl` and `tar` for downloads.

## License

Apache-2.0
