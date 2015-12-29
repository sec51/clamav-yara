### WORK IN PROGRESS

[![Build Status](https://travis-ci.org/sec51/clamav-yara.svg?branch=master)](https://travis-ci.org/sec51/clamav-yara)

===

### Clamav To Yara [WORK IN PROGRESS]

* Downloads the definitions periodically from clamav

* Checks the definitions were changes via Etag

* Checks the hash of the definitions files is valid

* Extract the signatures and generate YARA rules

===

### TODO

* Create a general way of parsing different signature formats. At the moment we are dealing only with NDB signatures, but there are a lot of commonalities with other formats.

* Use FILE module on OSX and LINUX to detect the file type and scan that specific file only.

* Test if FILE, PE, ELF module cause memory leaks

===

### LICENSE

Copyright (c) 2015-2016 Sec51.com <info@sec51.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.