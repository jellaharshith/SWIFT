# SWIFT v8 vendored skills

Eight agent skills + twenty-three slash commands ported from
[shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
(MIT). Every filename carries a `swift-` prefix so they coexist with
`gstack`, `superpowers`, `caveman`, and any other installed skill packs.

## Install

```sh
swiftsec skills install            # symlink into ~/.claude/skills + ~/.claude/commands
swiftsec skills install --dry-run  # show what would change first
swiftsec skills uninstall          # remove the symlinks
swiftsec skills list               # show what is currently linked
```

`install` creates symlinks (not copies) so `git pull` on the SWIFT repo
updates the live skills automatically.

## External tool dependencies

The skills shell out to a number of Go / Rust scanners. Install them via
your OS package manager or by hand:

```sh
# macOS (brew)
brew install subfinder httpx nuclei katana ffuf nmap dnsx amass trufflehog gitleaks

# Linux (apt + go install for tools not in distro repos)
sudo apt install nmap
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

Optional API keys (in `~/.config/subfinder/config.yaml` or env vars):

* `CHAOS_API_KEY`     -- ProjectDiscovery Chaos
* `SHODAN_API_KEY`    -- Shodan search
* `SECURITYTRAILS_KEY` -- SecurityTrails
* `VT_API_KEY`        -- VirusTotal

The skills gracefully no-op when a tool is missing.

## License + attribution

These files are MIT-licensed in their original form. The `swift-` prefix is
the only modification; full credit stays with the upstream authors. See the
project-root `NOTICE` file.
