# Anon Media Uploader

Upload images and files to free hosts through rotating free proxies, save the hashes and links of every upload, and check later if they are still alive.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/anon-media-uploader/install.sh | bash
```

Installs the script and its modules (`aiohttp`, `aiohttp-socks`, `Pillow`) and adds the `media-drop` command.

Manual: `pip install -r requirements.txt` then `python media_drop.py ...`

## Features

- Images: catbox, imgbb, freeimage, pixhost, img.in.th, lensdump, imgur (key)
- Files: catbox, pomf.lain.la, qu.ax, gofile, 0x0.st, x0.at, paste.c-net.org, pixeldrain (key), litterbox, temp.sh, tmpfile.link, filebin, uguu, tmpfiles
- Hosts picked by file size and how long you want it kept (permanent / temporary / min-max life)
- Free proxies from ~30 public lists, validated before use (TLS always verified, IP-leak check), or Tor / your own proxy
- Optional hash change that keeps the file valid, and `restore` to get the original back
- Hash manifest (MD5 / SHA-1 / SHA-256 / dHash) per host, and a plain links file
- Link checker: intact, re-encoded, changed, removed, expired

## Usage

### Images

```bash
media-drop upload image.jpg
media-drop upload image.jpg --all --save-hashes
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

- `none` upload as-is (default)
- `safe` hidden marker the format allows (file still opens normally)
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
