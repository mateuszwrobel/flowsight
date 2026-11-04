//! Declared cross-process topology. Channels are drawn ONLY from a
//! declared-topology toml; every anchor in that file must resolve to a fn
//! definition in the analyzed source set. A stale anchor fails the run
//! closed and names the anchor (refuse-to-draw-unproven).

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::extract::FlowError;
use crate::model::{EdgeKind, Prov};
use crate::source::SourceSet;

/// A declared topology: named processes plus the hops between them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    pub process: Vec<String>,
    pub hop: Vec<Hop>,
}

/// One declared cross-process hop. `from` and `to` are code anchors:
/// a root-relative file and a fn name defined in that file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub from_process: String,
    pub to_process: String,
    pub transport: String,
    pub from: Anchor,
    pub to: Anchor,
}

/// A code anchor inside the declared topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub file: String,
    pub symbol: String,
}

impl fmt::Display for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.symbol)
    }
}

impl Topology {
    /// Parse a `topology.toml`. Undeclared endpoint processes are a config
    /// error: a hop must connect two names the file itself declares.
    pub fn load(path: &Path) -> Result<Self, FlowError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| FlowError::Io(format!("cannot read {}: {e}", path.display())))?;
        let top: Topology = toml::from_str(&text)
            .map_err(|e| FlowError::Config(format!("{}: {e}", path.display())))?;
        for hop in &top.hop {
            for p in [&hop.from_process, &hop.to_process] {
                if !top.process.iter().any(|d| d == p) {
                    return Err(FlowError::Config(format!(
                        "hop {p} -> {} names process `{p}` that the process list does not declare",
                        hop.to_process
                    )));
                }
            }
        }
        Ok(top)
    }

    /// Resolve every anchor against the source set and return the endpoint
    /// nodes plus the channel edges. Any anchor that no longer names a fn
    /// definition in its declared file is a stale anchor: the whole run
    /// fails and names it. Each hop draws `fn -> PROCESS -> fn`, each half
    /// proven by the anchor line it starts from.
    pub fn resolve(
        &self,
        set: &SourceSet,
    ) -> Result<(Vec<crate::model::Node>, Vec<crate::model::Edge>), FlowError> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        for hop in &self.hop {
            let from = self.resolve_anchor(set, hop, &hop.from)?;
            let to = self.resolve_anchor(set, hop, &hop.to)?;
            for name in [&hop.from_process, &hop.to_process] {
                nodes.push(crate::model::Node {
                    id: process_node(name),
                    kind: crate::model::NodeKind::Process,
                    label: name.clone(),
                    def: None,
                });
            }
            edges.push(crate::model::Edge {
                src: from.0.clone(),
                dst: process_node(&hop.from_process),
                kind: EdgeKind::Channel,
                prov: from.1,
            });
            edges.push(crate::model::Edge {
                src: process_node(&hop.from_process),
                dst: process_node(&hop.to_process),
                kind: EdgeKind::Channel,
                prov: to.1.clone(),
            });
            edges.push(crate::model::Edge {
                src: process_node(&hop.to_process),
                dst: to.0.clone(),
                kind: EdgeKind::Channel,
                prov: to.1,
            });
        }
        Ok((nodes, edges))
    }

    fn resolve_anchor(
        &self,
        set: &SourceSet,
        hop: &Hop,
        anchor: &Anchor,
    ) -> Result<(String, Prov), FlowError> {
        let detail = format!("hop {} -> {}", hop.from_process, hop.to_process);
        let fi = set.files.iter().position(|f| f.path == anchor.file).ok_or_else(|| {
            FlowError::StaleAnchor {
                anchor: anchor.to_string(),
                detail: format!("{detail}: no such file in the source set"),
            }
        })?;
        let found = set.files[fi]
            .fns
            .iter()
            .find(|o| o.name == anchor.symbol && !o.in_test_region);
        match found {
            Some(o) => {
                let id = match &o.owner {
                    crate::source::FnOwner::Free => {
                        format!("{}::{}", set.files[fi].module, o.name)
                    }
                    crate::source::FnOwner::Impl(t) | crate::source::FnOwner::Trait(t) => {
                        format!("{}::{}::{}", set.files[fi].krate, t, o.name)
                    }
                };
                Ok((id, Prov::new(anchor.file.clone(), set.files[fi].line_of(o.offset))))
            }
            None => Err(FlowError::StaleAnchor {
                anchor: anchor.to_string(),
                detail: format!("{detail}: no fn `{}` defined in this file", anchor.symbol),
            }),
        }
    }
}

/// The process endpoint node ids for the html/json emitters.
#[must_use]
pub fn process_node(name: &str) -> String {
    format!("PROCESS:{name}")
}
