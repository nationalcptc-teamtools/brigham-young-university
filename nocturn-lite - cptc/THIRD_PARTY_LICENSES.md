# Third-Party Licenses

This product bundles the Go modules listed below. Each is distributed under its
own license, reproduced from the version in the project's module cache. All are
permissive (MIT / BSD-3-Clause) and impose no source-disclosure obligation on
this product; the only requirement is that these copyright and permission
notices accompany any distribution.

To regenerate this file precisely (recommended before each release):

```sh
go install github.com/google/go-licenses@latest
go-licenses report . > THIRD_PARTY_LICENSES.txt   # or 'save' to copy full texts
```

| Module | Version | License |
|---|---|---|
| github.com/atotto/clipboard | v0.1.4 | BSD-3-Clause |
| github.com/charmbracelet/bubbles | v0.20.0 | MIT |
| github.com/charmbracelet/bubbletea | v1.2.4 | MIT |
| github.com/charmbracelet/lipgloss | v1.0.0 | MIT |
| github.com/charmbracelet/x/ansi | v0.4.5 | MIT |
| github.com/charmbracelet/x/term | v0.2.1 | MIT |
| github.com/aymanbagabas/go-osc52/v2 | v2.0.1 | MIT |
| github.com/erikgeiser/coninput | v0.0.0-20211004153227 | MIT |
| github.com/lucasb-eyer/go-colorful | v1.2.0 | MIT |
| github.com/mattn/go-isatty | v0.0.20 | MIT |
| github.com/mattn/go-localereader | v0.0.1 | MIT (per upstream repository; module ships no LICENSE file) |
| github.com/mattn/go-runewidth | v0.0.16 | MIT |
| github.com/muesli/ansi | v0.0.0-20230316100256 | MIT |
| github.com/muesli/cancelreader | v0.2.2 | MIT |
| github.com/muesli/termenv | v0.15.2 | MIT |
| github.com/rivo/uniseg | v0.4.7 | MIT |
| github.com/sahilm/fuzzy | v0.1.1 | MIT |
| golang.org/x/sync | v0.9.0 | BSD-3-Clause |
| golang.org/x/sys | v0.27.0 | BSD-3-Clause |
| golang.org/x/text | v0.3.8 | BSD-3-Clause |

## MIT License

Applies to all modules marked "MIT" above. Copyright holders include, without
limitation: Charmbracelet, Inc.; Ayman Bagabas; Erik Geiser; Lucas Beyer;
Yasuhiro Matsumoto; Christian Muehlhaeuser; Oliver Kuederle; Sahil Muthoo.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## BSD-3-Clause License

Applies to `github.com/atotto/clipboard` (Copyright (c) 2013 Ato Araki) and the
`golang.org/x/*` modules (Copyright (c) 2009 The Go Authors).

```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
   3. Neither the name of the copyright holder nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Bundled wordlists

The `wordlists/` directory is derived from third-party data sets. See
`wordlists/ATTRIBUTION.md` for their sources and terms.
