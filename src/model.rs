//! Canonical flow model: nodes, edges, provenance, and the unresolved
//! report. Every collection is sorted, so two renders of the same graph
//! are byte-identical (determinism law, specs/investigations/flowsight.md).
//!
//! The edge contract: an edge exists only if it carries `file:line`
//! provenance read from real source. There is no confidence field BY
//! DESIGN — provenance is binary, not graded trust.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// A provenance pointer: root-relative file plus 1-based line. Paths use
/// `/` separators and never an absolute prefix, so two runs are identical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Prov {
    pub file: String,
    pub line: usize,
}

impl Prov {
    #[must_use]
    pub fn new(file: impl Into<String>, line: usize) -> Self {
        Self {
            file: file.into(),
            line,
        }
    }
}

/// Node classes drawn by the emitters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// An HTTP route arm (verb + path pattern).
    Route,
    /// A function or method whose definition was read from source, or a
    /// named call target at a source boundary.
    Fn,
    /// A table declared in the dbgraph schema join.
    Table,
    /// A declared external process (cross-process channel endpoint).
    Process,
}

/// A graph node. `id` is stable and unique; `label` is the display text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    /// Definition site, when the definition was found in the source set.
    pub def: Option<Prov>,
}

/// Edge classes. Every kind is proven by `Edge::prov`; the html renderer
/// styles `channel` differently because it crosses a process boundary
/// and comes only from the declared topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Route arm -> handler, or route -> inline call target.
    Route,
    /// A typed call site: caller -> resolved callee.
    Call,
    /// dyn-trait dispatch hop: trait method -> implementing type method,
    /// proven by the single `impl` declaration site in the source set.
    Dispatch,
    /// Store method -> table touched by an SQL literal read from source.
    Sql,
    /// Cross-process hop, drawn only from the declared-topology toml.
    Channel,
}

/// One directed edge. Ordering is (src, dst, kind, prov) so the emitted
/// edge list is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edge {
    pub src: String,
    pub dst: String,
    pub kind: EdgeKind,
    pub prov: Prov,
}

/// A graph node keyed by id, an edge set, and the unresolved report.
/// `unresolved` lines name exactly what could not be proven and where.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowGraph {
    pub nodes: BTreeMap<String, Node>,
    pub edges: BTreeSet<Edge>,
    pub unresolved: BTreeSet<String>,
}

impl FlowGraph {
    pub fn node(&mut self, id: impl Into<String>, kind: NodeKind, label: impl Into<String>, def: Option<Prov>) {
        let id = id.into();
        let label = label.into();
        let entry = self.nodes.entry(id.clone()).or_insert_with(|| Node {
            id,
            kind,
            label,
            def: None,
        });
        // A later definition sight only refines an unknown node; the first
        // kind stays authoritative so re-sighting cannot rewrite a route.
        if entry.def.is_none() {
            entry.def = def;
        }
    }

    pub fn edge(&mut self, src: impl Into<String>, dst: impl Into<String>, kind: EdgeKind, prov: Prov) {
        self.edges.insert(Edge {
            src: src.into(),
            dst: dst.into(),
            kind,
            prov,
        });
    }

    pub fn unresolved(&mut self, line: impl Into<String>) {
        self.unresolved.insert(line.into());
    }

    /// Node ids referenced by at least one edge; nodes outside this set
    /// were created but ended up with no proven edge (refuse-to-draw).
    #[must_use]
    pub fn drawn_node_ids(&self) -> BTreeSet<String> {
        let mut used = BTreeSet::new();
        for e in &self.edges {
            used.insert(e.src.clone());
            used.insert(e.dst.clone());
        }
        used
    }
}

/// Deterministic run metadata embedded in the json artefact. No absolute
/// paths, no timestamps — only declared, stable content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub schema_version: u32,
    pub name: String,
    pub crates: Vec<String>,
}

/// The whole emitted model: graph + meta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Model {
    pub meta: Meta,
    pub graph: FlowGraph,
}
