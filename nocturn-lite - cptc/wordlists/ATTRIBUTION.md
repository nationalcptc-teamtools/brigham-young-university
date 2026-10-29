# Wordlist Attribution

The wordlists bundled in this directory are redistributed from **SecLists**
(https://github.com/danielmiessler/SecLists), a collection maintained by Daniel
Miessler, Jason Haddix, g0tmi1k and contributors. SecLists is distributed under
the **MIT License**, which permits redistribution — including in a commercial
product — provided the copyright and permission notice travel with it.

```
MIT License

Copyright (c) 2012-2024 Daniel Miessler, Jason Haddix, g0tmi1k and contributors

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

## Upstream sources of individual files

Several lists in SecLists originate from other projects and carry their own
attribution. The ones bundled here:

| File(s) | Upstream source | Notes |
|---|---|---|
| `web-content/DirBuster-2007_directory-list-2.3-medium.txt` | OWASP DirBuster project | Authored by the DirBuster project; redistributed via SecLists. |
| `web-content/raft-*.txt` | RAFT (Response Analysis and Further Testing) project | Generated from real-world crawls; redistributed via SecLists. |
| `web-content/big.txt`, `common.txt`, `quickhits.txt` | SecLists / dirb | Compiled from the `dirb` tool's lists and community contributions. |
| `dns/subdomains-top1million-*.txt` | assetnote / community | Common-subdomain frequency lists. |
| `dns/bitquark-subdomains-top100000.txt` | bitquark research | Published subdomain research set. |
| `passwords/probable-v2_top-*.txt` | berzerk0 "Probable Wordlists" | Ranked by observed frequency. |
| `passwords/Pwdb_top-100000.txt` | PWDB (Password Database) research | Top passwords by frequency. |
| `passwords/darkweb2017_top-1000.txt` | SecLists | Frequency-ranked leaked-password sample. |
| `usernames/cirt-default-usernames.txt` | CIRT.net default-credentials database | Vendor default usernames. |
| `*-shortlist.txt` | SecLists | Small curated subsets. |

These files contain no personal data beyond common/leaked credential *strings*
used for authorized security testing. If you prefer not to redistribute them at
all, remove this directory and have `install.sh` fetch SecLists at install time
instead (see the note in `install.sh`); the application resolves wordlists by
path at runtime, so either approach works.
