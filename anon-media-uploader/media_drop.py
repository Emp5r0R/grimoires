#!/usr/bin/env python3
"""media_drop - upload images and files to free hosts through rotating free proxies.

Thin launcher; the code lives in the `mediadrop` package next to this file:

  util.py        errors, time/size/duration helpers, atomic writes
  media.py       type sniffing, hashes, perceptual hash, metadata strip, payloads
  rehash.py      change a file's hash without breaking it, and restore it
  net.py         proxy values, HTTP clients, error classification
  proxies.py     free proxy discovery, validation, cache, rotation
  hosts/         one class per host (image_hosts.py, file_hosts.py) + registry
  selection.py   pick hosts by size / permanence / lifetime
  engine.py      retries with proxy rotation and backoff
  uploader.py    upload service shared by `upload` and `file`
  manifest.py    hash manifest (JSON) and link list (TSV)
  checker.py     fetch + hash + classify hosted copies
  cli.py         argument parsing and commands
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mediadrop.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
