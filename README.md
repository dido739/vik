# vik

`vik` (Version Integrity Kit) is a local, Rust-based version control CLI with:

- content-addressed object storage (SHA-256)
- blob/tree/commit object types
- staging index
- commit history via refs + `HEAD`
- basic branching and checkout

## Commands

- `vik init [path]`
- `vik hash-object <file> [--write]`
- `vik cat-file (--type|--size|-p) <object>`
- `vik add <files...>`
- `vik commit -m <message>`
- `vik log`
- `vik branch [name]`
- `vik checkout <name>`
- `vik status`