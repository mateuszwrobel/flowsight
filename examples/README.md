# flowsight examples — pointer

An `analyze` run over a real tree spells its entry surfaces with flags:

```sh
flowsight analyze <repo-root> --crate <crate-dir> [--crate <dir>...] \
    --seed <file.rs>:<fn> --derive-schema --topology <topology.toml> \
    --name <name>
```

- `--seed` roots an extra walk at a declared `file:symbol` anchor — the
  entry surfaces beyond HTTP routes (a tool surface, a job loop).
- `--derive-schema` reads the `CREATE TABLE` literals from the analyzed
  source itself; no table is ever guessed.
- `--topology` declares cross-process hops; each anchor must name a
  definition or the run fails.

Generated flow docs belong with the project that generates them — keep
your run profile and committed artifacts in your own repository, next to
your documentation, not inside this crate.
