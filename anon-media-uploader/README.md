# Anon Media Uploader

Upload images/media to free hosts through rotating free proxies, save the hashes of every upload per host, and check later if the links are still alive.

## Features

- 16 hosts: catbox, imgbb, freeimage, pixhost, img.in.th, pomf.lain.la, qu.ax, x0.at, 0x0.st, lensdump, imgur (key), litterbox, uguu, tmpfiles, temp.sh, filebin
- Free proxies from ~30 public lists, validated before use (TLS always verified, IP-leak check)
- Tor and your own proxies supported
- Failover between hosts, or mirror one file to many hosts
- Hash manifest (MD5 / SHA-1 / SHA-256 / dHash) per host
- Link checker: intact, re-encoded, changed, removed, expired
- Optional EXIF/GPS stripping, random filenames

## Requirements

- Python 3.9+
- `aiohttp`
- `aiohttp-socks` (optional, SOCKS/Tor)
- `Pillow` (optional, `--strip-metadata` and dHash)

```bash
pip install aiohttp aiohttp-socks Pillow
```

## Usage

### Upload

```bash
python media_drop.py upload image.jpg
```

Prints the URL. Tries hosts in order until one works.

### Upload to every host and save hashes

```bash
python media_drop.py upload image.jpg --all --save-hashes
```

Hashes and links go to `media_hashes.json` (or pass your own file: `--save-hashes my.json`).

### Check if uploads are still there

```bash
python media_drop.py check
python media_drop.py check --manifest my.json
```

Check a single link:

```bash
python media_drop.py check https://files.catbox.moe/abc.jpg --expect-sha256 HASH
```

### Other commands

```bash
python media_drop.py list --csv          # export manifest
python media_drop.py hosts               # supported hosts
python media_drop.py proxies --export proxies.txt
```

### Useful options

```bash
--hosts catbox,imgbb       # pick hosts (or: permanent, temporary, images, all)
--mirror 3                 # upload to 3 hosts
--strip-metadata           # remove EXIF/GPS first
--expire 1d                # auto delete where supported
--tor                      # use Tor instead of free proxies
--proxy socks5://ip:port   # use your own proxy
--direct                   # no proxy
```

## Help

```bash
python media_drop.py --help
python media_drop.py upload --help
python media_drop.py check --help
```

## Note

Free proxies are slow and unreliable; finding working ones can take a minute. Use `--tor` or your own proxy for better results.
