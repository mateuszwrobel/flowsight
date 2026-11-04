# flowsight

Static, provenance-first data-flow extraction for Rust trees. `flowsight
analyze` reads source read-only and emits a flow model as json plus one
self-contained interactive html. Every edge carries the exact `file:line`
it was extracted from. There are no confidence scores: an edge either has
provenance or the run refuses and names the ambiguity.

## Guarantees

- **Refuse-to-draw-unproven.** An edge exists only when a source line
  proves it (a route arm, a resolved call, a typed field, an SQL literal
  joined to the declared schema, or a dispatch the construction site
  pins). Anything else is absent or the run fails.
- **Ambiguity fails closed.** A bare call or dyn dispatch with several
  in-scope candidates stops the run and lists every candidate with its
  `file:line`.
- **Stale anchors fail closed.** Cross-process hops come only from a
  declared `topology.toml`. Every anchor in it must name a definition in
  that file; a stale anchor aborts the run and names the anchor.
- **Deterministic.** Two runs over the same tree produce byte-identical
  output (enforced by a test).

## Install

From a checkout of this repository:

```sh
cargo install --path .
```

Or fetch a released binary through npm:

```sh
npm install "@<scope>/flowsight"    # <scope> is the scope the release announces
npx "@<scope>/flowsight" analyze . --crate <dir>   # or run it without installing
```

See [npm/README.md](npm/README.md) for how the npm package fetches and
verifies the binary.

## Usage

```sh
flowsight analyze <root> --crate <dir> [--crate <dir>...] \
    [--app App] [--topology topology.toml] [--schema-tables a,b | --derive-schema] \
    [--seed <file.rs>:<fn>] [--out <dir>] [--name <name>]
```

- `--crate` picks the crate directories to index (relative to `<root>`).
- `--app` names the state struct the route handlers receive (default `App`).
- `--derive-schema` reads `CREATE TABLE` literals from the source itself;
  `--schema-tables` declares the table list instead. An SQL literal that
  names a table outside that list is reported unresolved, never guessed.
- `--seed` roots an extra walk at a declared `file:symbol` anchor — use it
  for entry surfaces beyond HTTP routes (a tool surface, a job loop).
- `--topology` adds declared cross-process hops; each anchor resolves to
  a definition or the run fails.

Outputs into `--out`: `flowsight.model.json` (the flow model),
`flowsight.html` (self-contained, vendored mermaid, provenance links per
edge) and `provenance.json` (the per-edge manifest plus the unresolved
list — what the run declined to draw, named site by site).

## Node spellings

| node        | example                                  |
|-------------|------------------------------------------|
| route       | `ROUTE:POST /api/orders`                 |
| function    | `inventory-core::Inventory::create_order` |
| table       | `TABLE:order`                            |
| process     | `PROCESS:inventoryd` (declared topology) |

Edge kinds: `route` (arm → handler), `call` (resolved call), `dispatch`
(trait object → the impl its construction site names), `sql` (function →
declared table), `channel` (declared cross-process hop).

## Example

`examples/README.md` shows how a full `analyze` run is spelled against a
real tree, including the `--seed` anchor for entry surfaces beyond HTTP
routes and the declared topology hops. Generated flow docs belong to the
project that generates them, not to this crate.

## Limits (phase 1+2)

Extraction is lexical (regex over a comment- and string-masked copy), not
a full parse. Macro-generated definitions are not in scope and are named
in the unresolved list. `#[cfg(test)]` regions and `tests/` directories
are excluded. Cross-process hops exist only as declared topology.
