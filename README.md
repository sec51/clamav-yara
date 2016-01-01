### Convert ClamAV definitions to Yara rules [![Build Status](https://travis-ci.org/sec51/clamav-yara.svg?branch=master)](https://travis-ci.org/sec51/clamav-yara)

===

### Clamav To Yara features:

* Downloads the definitions periodically from clamav: at the moment hard coded in main.go to 4 hours

* Checks the definitions were changes via Etag

* ON HOLD: Checks the hash of the definitions files is valid. Got around it by installing clamav on our servers with freshclam and setting the URLs to our servers, which downloads in HTTPS

* Extract the signatures and generate YARA rules. At the moment the ClamAV file parsed are: NDB, HDB, HSB. MDB and MSB are done as well, but need to find a way to generate proper YARA rules with that.

===

### How to generate the rules

```
git clone https://github.com/sec51/clamav-yara.git

go build

go test -v

./clamav-yara
```

You can then find the generated Yara rules inside the `rules` folder

===

### TODO

* Use FILE module on OSX and LINUX to detect the file type and scan that specific file only.

* Test if FILE, PE, ELF module cause memory leaks

* Wait for Golang 1.6 and hope that they introduce the {{- end}} tag in the template package, to remove the empty spaces.

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