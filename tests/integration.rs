//! End-to-end behaviour: the route-to-table chain, byte-level determinism,
//! and the two refusals (stale anchor, ambiguous call) on synthetic crates.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use flowsight::model::{EdgeKind, Meta, Model, NodeKind};
use flowsight::render::model_json;
use flowsight::topology::Topology;
use flowsight::{AnalyzeConfig, FlowError, analyze};

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A tiny web crate: route arm -> handler -> typed field -> sql -> table.
fn web_crate(root: &Path) {
    write(
        &root.join("web/Cargo.toml"),
        "[package]\nname = \"web\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write(
        &root.join("web/src/main.rs"),
        r#"
use std::sync::Arc;

pub struct Store {
    pub db: String,
}

impl Store {
    pub fn put(&self, key: &str) {
        self.exec("INSERT INTO widgets (id) VALUES (?1)");
    }

    fn exec(&self, sql: &str) {
        let _ = sql;
    }
}

pub struct App {
    pub store: Arc<Store>,
}

fn main() {}

fn handle_create(app: &App, body: &str) {
    app.store.put(body);
}

pub fn route(app: &App, method: &str, path: &str) {
    match (method, path) {
        ("POST", ["api", "widgets"]) => handle_create(app, "x"),
        _ => {}
    }
}
"#,
    );
}

fn cfg(root: &Path) -> AnalyzeConfig {
    AnalyzeConfig {
        root: root.to_path_buf(),
        crates: vec![PathBuf::from("web")],
        app_struct: "App".to_string(),
        schema_tables: Some(BTreeSet::from(["widgets".to_string()])),
        seeds: Vec::new(),
    }
}

fn has_edge(graph: &flowsight::model::FlowGraph, src: &str, dst: &str, kind: EdgeKind) -> bool {
    graph
        .edges
        .iter()
        .any(|e| e.src == src && e.dst == dst && e.kind == kind)
}

#[test]
fn route_handler_store_table_chain() {
    let tmp = tempfile::tempdir().unwrap();
    web_crate(tmp.path());
    let (_set, graph) = &analyze(&cfg(tmp.path())).unwrap();
    assert!(has_edge(
        graph,
        "ROUTE:POST /api/widgets",
        "web::handle_create",
        EdgeKind::Route
    ));
    assert!(has_edge(
        graph,
        "web::handle_create",
        "web::Store::put",
        EdgeKind::Call
    ));
    assert!(has_edge(
        graph,
        "web::Store::put",
        "web::Store::exec",
        EdgeKind::Call
    ));
    assert!(has_edge(graph, "web::Store::put", "TABLE:widgets", EdgeKind::Sql));
    for e in &graph.edges {
        assert!(!e.prov.file.is_empty(), "edge {} -> {e:?} lacks provenance", e.src);
    }
}

#[test]
fn two_runs_are_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    web_crate(tmp.path());
    let model = |graph: flowsight::model::FlowGraph| Model {
        meta: Meta {
            schema_version: 1,
            name: "t".to_string(),
            crates: vec!["web".to_string()],
        },
        graph,
    };
    let (_, g1) = analyze(&cfg(tmp.path())).unwrap();
    let (_, g2) = analyze(&cfg(tmp.path())).unwrap();
    assert_eq!(model_json(&model(g1)), model_json(&model(g2)));
}

#[test]
fn ambiguous_bare_call_refuses_the_run() {
    let tmp = tempfile::tempdir().unwrap();
    web_crate(tmp.path());
    write(
        &tmp.path().join("web/src/extra_a.rs"),
        "pub fn shared_handler(app: &App) { let _ = app; }\n",
    );
    write(
        &tmp.path().join("web/src/extra_b.rs"),
        "pub fn shared_handler(app: &App) { let _ = app; }\n",
    );
    write(
        &tmp.path().join("web/src/main.rs"),
        &std::fs::read_to_string(tmp.path().join("web/src/main.rs"))
            .unwrap()
            .replace("handle_create(app, \"x\")", "shared_handler(app)"),
    );
    let err = analyze(&cfg(tmp.path())).expect_err("ambiguous call must refuse");
    match err {
        FlowError::Ambiguous { what, candidates, .. } => {
            assert!(what.contains("shared_handler"), "names the call: {what}");
            assert_eq!(candidates.len(), 2, "names both candidates: {candidates:?}");
        }
        other => panic!("expected Ambiguous, got {other}"),
    }
}

#[test]
fn stale_anchor_refuses_the_run() {
    let tmp = tempfile::tempdir().unwrap();
    web_crate(tmp.path());
    write(
        &tmp.path().join("topology.toml"),
        r#"
process = ["web", "worker"]

[[hop]]
from_process = "web"
to_process = "worker"
transport = "tcp"

[hop.from]
file = "web/src/main.rs"
symbol = "gone_fn"

[hop.to]
file = "web/src/main.rs"
symbol = "main"
"#,
    );
    let (set, _graph) = &analyze(&cfg(tmp.path())).unwrap();
    let top = Topology::load(&tmp.path().join("topology.toml")).unwrap();
    let err = top.resolve(set).expect_err("stale anchor must refuse");
    match err {
        FlowError::StaleAnchor { anchor, .. } => {
            assert_eq!(anchor, "web/src/main.rs:gone_fn");
        }
        other => panic!("expected StaleAnchor, got {other}"),
    }
}

#[test]
fn resolved_hop_draws_channel_edges() {
    let tmp = tempfile::tempdir().unwrap();
    web_crate(tmp.path());
    write(
        &tmp.path().join("worker/Cargo.toml"),
        "[package]\nname = \"worker\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write(
        &tmp.path().join("worker/src/main.rs"),
        "fn main() {}\npub fn consume() {}\n",
    );
    write(
        &tmp.path().join("topology.toml"),
        r#"
process = ["web", "worker"]

[[hop]]
from_process = "web"
to_process = "worker"
transport = "tcp"

[hop.from]
file = "web/src/main.rs"
symbol = "handle_create"

[hop.to]
file = "worker/src/main.rs"
symbol = "consume"
"#,
    );
    let cfg = AnalyzeConfig {
        crates: vec![PathBuf::from("web"), PathBuf::from("worker")],
        ..cfg(tmp.path())
    };
    let (set, _graph) = &analyze(&cfg).unwrap();
    let top = Topology::load(&tmp.path().join("topology.toml")).unwrap();
    let (nodes, edges) = top.resolve(set).unwrap();
    assert!(
        nodes
            .iter()
            .any(|n| n.kind == NodeKind::Process && n.id == "PROCESS:worker")
    );
    assert_eq!(edges.len(), 3, "each hop draws fn -> PROCESS -> PROCESS -> fn");
    assert!(has_edges(
        &edges,
        &[
            ("web::handle_create", "PROCESS:web"),
            ("PROCESS:web", "PROCESS:worker"),
            ("PROCESS:worker", "worker::consume"),
        ]
    ));
}

fn has_edges(edges: &[flowsight::model::Edge], want: &[(&str, &str)]) -> bool {
    want.iter().all(|(s, d)| {
        edges
            .iter()
            .any(|e| e.src == *s && e.dst == *d && e.kind == EdgeKind::Channel)
    })
}

#[test]
fn unknown_table_mention_is_unresolved_not_invented() {
    let tmp = tempfile::tempdir().unwrap();
    web_crate(tmp.path());
    let cfg = AnalyzeConfig {
        schema_tables: Some(BTreeSet::new()),
        ..cfg(tmp.path())
    };
    let (_set, graph) = &analyze(&cfg).unwrap();
    assert!(
        graph
            .unresolved
            .iter()
            .any(|u| u.contains("widgets") && u.contains("not in the declared schema"))
    );
    assert!(
        !graph.edges.iter().any(|e| e.dst.starts_with("TABLE:")),
        "an undeclared table must not gain an edge"
    );
}
