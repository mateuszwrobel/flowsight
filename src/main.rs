//! flowsight CLI: analyze a tree, emit flow-model json + one self-contained
//! html + a provenance manifest. Refusals (ambiguity, stale anchor) exit 1
//! and name the exact site on stderr.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use flowsight::model::{Meta, Model, NodeKind};
use flowsight::{AnalyzeConfig, FlowError, Topology, extract, render};

const MERMAID: &str = include_str!("../assets/mermaid.min.js");

fn main() -> ExitCode {
    // Version banner for the installer probe (specs/install/
    // install-spec-tools.sh): names the tool and the crate version, exits 0.
    if std::env::args()
        .nth(1)
        .is_some_and(|a| a == "--version" || a == "-V")
    {
        println!("flowsight {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("flowsight: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Args {
    root: PathBuf,
    crates: Vec<PathBuf>,
    app_struct: String,
    topology: Option<PathBuf>,
    schema_tables: Option<BTreeSet<String>>,
    derive_schema: bool,
    seeds: Vec<(String, String)>,
    out: PathBuf,
    name: String,
}

fn parse_args() -> Result<Args, FlowError> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut a = Args {
        root: PathBuf::from("."),
        crates: Vec::new(),
        app_struct: "App".to_string(),
        topology: None,
        schema_tables: None,
        derive_schema: false,
        seeds: Vec::new(),
        out: PathBuf::from("flowsight-out"),
        name: String::new(),
    };
    let mut argv = argv.into_iter();
    match argv.next().as_deref() {
        Some("analyze") | None => {}
        Some(other) => {
            return Err(FlowError::Config(format!("unknown command `{other}`: expected analyze")));
        }
    }
    let mut positional = false;
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--crate" => {
                let v = argv.next().ok_or_else(|| FlowError::Config("--crate needs a path".into()))?;
                a.crates.push(PathBuf::from(v));
            }
            "--app" => {
                a.app_struct = argv
                    .next()
                    .ok_or_else(|| FlowError::Config("--app needs a struct name".into()))?;
            }
            "--topology" => {
                a.topology = Some(PathBuf::from(
                    argv.next().ok_or_else(|| FlowError::Config("--topology needs a path".into()))?,
                ));
            }
            "--schema-tables" => {
                let v = argv
                    .next()
                    .ok_or_else(|| FlowError::Config("--schema-tables needs a list".into()))?;
                let mut set = BTreeSet::new();
                for t in v.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                    set.insert(t.to_string());
                }
                a.schema_tables = Some(set);
            }
            "--derive-schema" => a.derive_schema = true,
            "--seed" => {
                let v = argv
                    .next()
                    .ok_or_else(|| FlowError::Config("--seed needs file:symbol".into()))?;
                let (file, sym) = v
                    .rsplit_once(':')
                    .ok_or_else(|| FlowError::Config(format!("--seed `{v}`: expected file:symbol")))?;
                a.seeds.push((file.to_string(), sym.to_string()));
            }
            "--out" => {
                a.out = PathBuf::from(
                    argv.next().ok_or_else(|| FlowError::Config("--out needs a path".into()))?,
                );
            }
            "--name" => {
                a.name = argv
                    .next()
                    .ok_or_else(|| FlowError::Config("--name needs a value".into()))?;
            }
            other => {
                if other.starts_with("--") {
                    return Err(FlowError::Config(format!("unknown flag `{other}`")));
                }
                if positional {
                    return Err(FlowError::Config(format!("unexpected argument `{other}`")));
                }
                a.root = PathBuf::from(other);
                positional = true;
            }
        }
    }
    if a.name.is_empty() {
        a.name = a
            .root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "flow".to_string());
    }
    Ok(a)
}

fn run() -> Result<(), FlowError> {
    let a = parse_args()?;
    let topology = match &a.topology {
        Some(p) => Some(Topology::load(p)?),
        None => None,
    };
    let mut seeds: Vec<(String, String)> = topology
        .as_ref()
        .map(|t| {
            let mut s: Vec<(String, String)> = Vec::new();
            for h in &t.hop {
                s.push((h.from.file.clone(), h.from.symbol.clone()));
                s.push((h.to.file.clone(), h.to.symbol.clone()));
            }
            s
        })
        .unwrap_or_default();
    seeds.extend(a.seeds.iter().cloned());

    let schema = a.schema_tables.clone();
    let (set, mut graph) = flowsight::analyze(&AnalyzeConfig {
        root: a.root.clone(),
        crates: a.crates.clone(),
        app_struct: a.app_struct.clone(),
        schema_tables: if a.derive_schema {
            None
        } else {
            schema.clone()
        },
        seeds: seeds.clone(),
    })?;
    if a.derive_schema {
        let derived = extract::derive_schema_tables(&set);
        let mut cfg2 = AnalyzeConfig {
            root: a.root.clone(),
            crates: a.crates.clone(),
            app_struct: a.app_struct.clone(),
            schema_tables: Some(derived),
            seeds,
        };
        if let Some(decl) = &schema {
            cfg2.schema_tables.get_or_insert_with(BTreeSet::new).extend(decl.clone());
        }
        (_, graph) = flowsight::analyze(&cfg2)?;
    }

    if let Some(top) = &topology {
        let (nodes, edges) = top.resolve(&set)?;
        for n in nodes {
            graph.nodes.entry(n.id.clone()).or_insert(n);
        }
        for e in edges {
            graph.edges.insert(e);
        }
    }

    // Refuse-to-draw-unproven, second half: a node with no proven edge is
    // dropped, so the artefacts only ever show what source proved.
    let drawn = graph.drawn_node_ids();
    graph.nodes.retain(|id, n| drawn.contains(id) || n.kind == NodeKind::Route);

    let model = Model {
        meta: Meta {
            schema_version: 1,
            name: a.name.clone(),
            crates: a.crates.iter().map(|c| c.to_string_lossy().replace('\\', "/")).collect(),
        },
        graph,
    };

    std::fs::create_dir_all(&a.out)
        .map_err(|e| FlowError::Io(format!("cannot create {}: {e}", a.out.display())))?;
    let json = render::model_json(&model);
    write(&a.out.join("flowsight.model.json"), &json)?;
    write(&a.out.join("flowsight.html"), &render::html(&model, MERMAID))?;
    write(&a.out.join("provenance.json"), &provenance_manifest(&model)?)?;

    let routes = model
        .graph
        .nodes
        .values()
        .filter(|n| n.kind == NodeKind::Route)
        .count();
    println!(
        "flowsight: {} nodes, {} edges, {} routes, {} unresolved -> {}",
        model.graph.nodes.len(),
        model.graph.edges.len(),
        routes,
        model.graph.unresolved.len(),
        a.out.join("flowsight.html").display()
    );
    Ok(())
}

/// Flat per-edge manifest: the provenance record of the run.
fn provenance_manifest(model: &Model) -> Result<String, FlowError> {
    let rows: Vec<serde_json::Value> = model
        .graph
        .edges
        .iter()
        .map(|e| {
            serde_json::json!({
                "src": e.src,
                "dst": e.dst,
                "kind": format!("{:?}", e.kind).to_lowercase(),
                "file": e.prov.file,
                "line": e.prov.line,
            })
        })
        .collect();
    let unresolved: Vec<&String> = model.graph.unresolved.iter().collect();
    let doc = serde_json::json!({
        "schema_version": 1,
        "name": model.meta.name,
        "edges": rows,
        "unresolved": unresolved,
    });
    let mut text = serde_json::to_string_pretty(&doc)
        .map_err(|e| FlowError::Config(format!("manifest: {e}")))?;
    text.push('\n');
    Ok(text)
}

fn write(path: &Path, text: &str) -> Result<(), FlowError> {
    std::fs::write(path, text).map_err(|e| FlowError::Io(format!("{}: {e}", path.display())))
}
