# SWIFT Brand Assets

## Color Palette

| Role | Hex | Usage |
|------|-----|-------|
| Primary | `#0EA5E9` | Shield outline, banner gradient start |
| Accent | `#22D3EE` | AI dot, banner gradient end |
| Danger | `#EF4444` | High-severity CLI table rows |
| Muted | `#64748B` | Secondary text, taglines |
| Background | `#0B1020` | Preferred dark surface |

## Files

- `swift_logo.svg` — Source vector. Edit this, then regenerate rasters.
- `swift_logo_{16,32,64,256,1024}.png` — Raster exports.
- `favicon.ico` — Browser favicon (16/32/48px multi-size).
- `swift_ascii.txt` — Terminal ASCII banner (ANSI Shadow font).

## Regenerate rasters

```bash
pip install cairosvg Pillow
bash assets/logo/build_rasters.sh
```
