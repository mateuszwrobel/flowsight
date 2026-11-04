//! flowsight — static, provenance-first data-flow extraction.
//!
//! Every edge in the output model carries the exact `file:line` it was
//! extracted from. There are no confidence scores: an edge either has
//! provenance or the run refuses and names the ambiguity.

pub mod extract;
pub mod model;
pub mod render;
pub mod source;
pub mod topology;

pub use extract::{AnalyzeConfig, FlowError, analyze};
pub use model::{Edge, EdgeKind, FlowGraph, Meta, Model, Node, NodeKind, Prov};
pub use render::{html, model_json};
pub use source::SourceSet;
pub use topology::Topology;
