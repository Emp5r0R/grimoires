# Grimoires

**About**: Contains useful and helpful scripts for various aspects. 


### Tools

| Tool | Command | What it does |
|------|---------|--------------|
| [github-email-scanAndScrub](github-email-scanAndScrub) | `email-guard` | scan and scrub leaked emails from Git history |
| [anon-media-uploader](anon-media-uploader) | `media-drop` | upload images/files through free proxies, save hashes and links, check them later |

### Install / update / remove / run any tool

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- install media-drop            # ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- install media-drop --system      # /usr/local/bin (asks for sudo)
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- update all
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- uninstall media-drop
curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- run media-drop --help          # no install, cleans up after
```

Windows (PowerShell):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.ps1))) install media-drop
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.ps1))) run media-drop --help
```

Installed tools can also update or remove themselves: `media-drop self-update`, `media-drop self-uninstall`.

### Rules for scripts in this repo

1. Scripts above 300 lines follow SOLID principles (one responsibility per module/class, extend by adding classes instead of editing existing ones, small interfaces, depend on abstractions).
2. Bigger scripts always ship with helper scripts (bash, PowerShell or whatever fits) - here [grimoire.sh](grimoire.sh) and [grimoire.ps1](grimoire.ps1).
3. Every installation/helper script can **install** (local folder or a folder on the system execution path), **update** and **uninstall/remove** the tool.
4. Every tool's README has a curl one-liner that runs the tool directly without installing it. If it cannot run without installing, the one-liner downloads it, runs it, gives the user the output and removes everything automatically so nothing is left behind.

### Caution

Use the code or snippets from here only for ethical purposes. You are responsible for whatever you do. 
