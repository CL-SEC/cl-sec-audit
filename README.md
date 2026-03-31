# cl-sec-audit

Scan installed Common Lisp systems for known
[CL-SEC](https://github.com/CL-SEC/cl-sec-advisories) vulnerabilities.

## Setup

Clone both repos as siblings:

```sh
git clone https://github.com/CL-SEC/cl-sec-advisories.git
git clone https://github.com/CL-SEC/cl-sec-audit.git
```

## Usage

```lisp
(asdf:load-system "cl-sec-audit")

;; Scan an ocicl project directory
(cl-sec-audit:audit :project-directory #p"~/git/my-project/")

;; Scan all loaded ASDF systems
(cl-sec-audit:audit)

;; Only show high/critical findings
(cl-sec-audit:audit :severity "high")

;; Check a single system
(cl-sec-audit:audit-system "ironclad")

;; Point to a custom advisory database location
(cl-sec-audit:audit :directory #p"/path/to/cl-sec-advisories/advisories/")
```

## How It Works

1. Enumerates installed systems via ocicl.csv, Quicklisp, or ASDF
2. Extracts version information (ocicl tags, QL dist dates, git hashes)
3. Matches against CL-SEC advisory `affected-dists` entries
4. Reports findings sorted by severity

## Dependencies

Only UIOP (bundled with ASDF). No external libraries required.

## License

Apache-2.0
