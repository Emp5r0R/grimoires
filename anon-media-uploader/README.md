# Anon Media Uploader

Upload images and files to free hosts through rotating free proxies, save the hashes and links of every upload, and check later if they are still alive.

## Run without installing

```bash
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- run media-drop upload image.jpg
```

Downloads the tool and its modules into a temp folder, runs it in your current folder (links/hash files are saved there) and deletes the temp folder afterwards.

Windows: `& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.ps1))) run media-drop upload image.jpg`

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- install media-drop            # local (~/.local/bin)
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- install media-drop --system   # /usr/local/bin
media-drop self-update
media-drop self-uninstall
```

Windows: `& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.ps1))) install media-drop` (add `--system` for all users)

Installs the script and its modules (`aiohttp`, `aiohttp-socks`, `Pillow`) in its own virtualenv and adds the `media-drop` command.

Manual: `pip install -r requirements.txt` then `python media_drop.py ...`

## Features

- Images: imgbb, freeimage, pixhost, imgur (key) + every file host below
- Files (permanent): catbox, pomf.lain.la, qu.ax, gofile, vikingfile, x0.at, paste.c-net.org, pixeldrain (key)
- Files (temporary): litterbox, transfer.adminforge.de, transfer.notkiska.pw, transfer.whalebone.io, temp.sh, tmpfile.link, filebin, sendit.sh, uguu, tmpfiles
- Paused by the sites themselves (kept, off by default): 0x0.st, img.in.th, lensdump - `media-drop hosts` shows why
- Hosts picked by file size and how long you want it kept (permanent / temporary / min-max life)
- Free proxies from ~30 public lists, validated before use (TLS always verified, IP-leak check), or Tor / your own proxy
- Pictures get a new hash on every host by default (file stays valid); `restore` gets the original back
- Hash manifest (MD5 / SHA-1 / SHA-256 / dHash) per host, and a plain links file
- Link checker: intact, re-encoded, changed, removed, expired

## Usage

### Images

Every host gets a slightly different copy (new hash and name each time, the picture itself is unchanged):

```bash
media-drop upload image.jpg
media-drop upload image.jpg --all --save-hashes
media-drop upload image.jpg --keep-hash        # upload the original bytes
```

### Files

```bash
media-drop file backup.zip                    # 3 hosts, prints all links
media-drop file backup.zip --save-links       # also save links to links.txt
media-drop file big.iso --keep temp           # temporary hosts only
media-drop file doc.pdf --keep perm --min-life 30d
```

### Change the hash

```bash
media-drop file doc.pdf --change-hash safe --save-hashes
media-drop file doc.pdf --change-hash safe --unique-per-host
```

- `auto` hidden marker the format allows, unchanged if there is none (default for images)
- `none` upload as-is (default for files)
- `safe` like auto, but formats without a marker go inside a zip
- `append` marker at the end of any file
- `wrap` original file inside a zip

Undo it on a downloaded copy:

```bash
media-drop restore downloaded.pdf
```

### Check uploads

```bash
media-drop check
media-drop check --manifest my.json
media-drop check https://files.catbox.moe/abc.jpg --expect-sha256 HASH
```

### Other

```bash
media-drop list --csv                 # export hashes and links
media-drop hosts                      # hosts, limits and retention
media-drop proxies --export proxies.txt
```

### Useful options

```bash
--hosts catbox,gofile      # pick hosts (or groups: permanent, temporary, images, files, all)
--mirror 3 / --all         # number of hosts per file
--expire 1d                # auto delete where supported
--strip-metadata           # remove EXIF/GPS from images
--tor                      # use Tor instead of free proxies
--proxy socks5://ip:port   # use your own proxy
--direct                   # no proxy
```

## Help

```bash
media-drop --help
media-drop file --help
```

## Note

Free proxies are slow and unreliable; finding working ones can take a minute. Use `--tor` or your own proxy for better results.
