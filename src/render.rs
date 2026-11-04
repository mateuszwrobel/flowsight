//! Emitters. The json render is canonical (BTreeMap/BTreeSet everywhere,
//! pretty-printed, trailing newline): two runs over the same source produce
//! identical bytes. The html render is one self-contained file: vendored
//! mermaid, no network, an interactive diagram per route plus a
//! provenance table that lists every drawn edge with its file:line.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::model::{Model, NodeKind};

/// Canonical flow-model json.
pub fn model_json(model: &Model) -> String {
    let mut text =
        serde_json::to_string_pretty(model).expect("model serializes: plain data only");
    text.push('\n');
    text
}

/// One self-contained interactive html: mermaid diagrams + provenance.
pub fn html(model: &Model, mermaid_js: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <title>flowsight: {}</title>\n<style>\n{}\n</style>\n</head>\n<body>\n",
        esc(&model.meta.name),
        CSS
    ));
    parts.push(format!(
        "<h1>flowsight &mdash; {}</h1>\n<p class=\"meta\">{} nodes &middot; {} edges \
         &middot; every edge proven by file:line &middot; no confidence scores</p>\n",
        esc(&model.meta.name),
        model.graph.nodes.len(),
        model.graph.edges.len()
    ));

    // One diagram per route, in model order (routes are sorted by id).
    let routes: Vec<&String> = model
        .graph
        .nodes
        .iter()
        .filter(|(_, n)| n.kind == NodeKind::Route)
        .map(|(id, _)| id)
        .collect();
    let mut diagram_scripts = String::new();
    for (i, route) in routes.iter().enumerate() {
        let (nodes, edges) = reachable(model, route);
        if edges.is_empty() {
            continue;
        }
        let mut dot = String::from("flowchart LR\n");
        let mut ids: BTreeMap<String, String> = BTreeMap::new();
        for n in &nodes {
            let m = format!("n{i}");
            ids.insert((*n).clone(), m.clone());
            let node = &model.graph.nodes[n.as_str()];
            let shape = match node.kind {
                NodeKind::Route => format!("{m}([\"{}\"])", esc(&node.label)),
                NodeKind::Table => format!("{m}[(`{}`)]", esc(&node.label)),
                NodeKind::Process => format!("{m}{{\"{}\"}}", esc(&node.label)),
                NodeKind::Fn => format!("{m}[\"{}\"]", esc(&node.label)),
            };
            dot.push_str(&format!("  {shape}\n"));
        }
        for e in edges {
            let a = &ids[&e.src];
            let b = &ids[&e.dst];
            let link = match e.kind {
                crate::model::EdgeKind::Route => "-->|route|",
                crate::model::EdgeKind::Call => "-->",
                crate::model::EdgeKind::Dispatch => "-->|impl|",
                crate::model::EdgeKind::Sql => "-->|sql|",
                crate::model::EdgeKind::Channel => "-.->|channel|",
            };
            dot.push_str(&format!("  {a} {link} {b}\n"));
        }
        parts.push(format!(
            "<h2>{}</h2>\n<div class=\"diagram\" id=\"d{i}\"></div>\n",
            esc(route)
        ));
        diagram_scripts
            .push_str(&format!("draw(\"#d{i}\", `{}`);\n", dot.replace('`', "'")));
    }

    parts.push("<h2>provenance</h2>\n<table>\n<tr><th>edge</th><th>kind</th><th>provenance</th></tr>\n".to_string());
    let mut edges: Vec<_> = model.graph.edges.iter().collect();
    edges.sort();
    for e in edges {
        parts.push(format!(
            "<tr><td class=\"mono\">{} &rarr; {}</td><td>{}</td><td class=\"mono\">{}</td></tr>\n",
            esc(&e.src),
            esc(&e.dst),
            kind_name(e.kind),
            prov_link(&e.prov.file, e.prov.line, &model.meta.name),
        ));
    }
    parts.push("</table>\n".to_string());
    if !model.graph.unresolved.is_empty() {
        parts.push("<h2>unresolved (not drawn)</h2>\n<ul>\n".to_string());
        for u in &model.graph.unresolved {
            parts.push(format!("<li class=\"mono\">{}</li>\n", esc(u)));
        }
        parts.push("</ul>\n".to_string());
    }
    parts.push(format!(
        "<script>\n{mermaid_js}\n</script>\n<script>\nmermaid.initialize({{startOnLoad:false, securityLevel:'strict'}});\n\
         function draw(sel, def) {{ const el = document.querySelector(sel); const id = 'g' + Math.random().toString(36).slice(2);\n\
         mermaid.render(id, def).then(r => {{ el.innerHTML = r.svg; }}); }}\n{diagram_scripts}</script>\n</body>\n</html>\n"
    ));
    parts.concat()
}

fn prov_link(file: &str, line: usize, _name: &str) -> String {
    format!("{file}:{line}")
}

fn kind_name(k: crate::model::EdgeKind) -> &'static str {
    use crate::model::EdgeKind::*;
    match k {
        Route => "route",
        Call => "call",
        Dispatch => "dispatch",
        Sql => "sql",
        Channel => "channel",
    }
}

/// Nodes and edges reachable from one root, deterministic order.
fn reachable<'m>(model: &'m Model, root: &'m str) -> (Vec<&'m String>, Vec<&'m crate::model::Edge>) {
    let mut adj: BTreeMap<&str, Vec<&crate::model::Edge>> = BTreeMap::new();
    for e in &model.graph.edges {
        adj.entry(&e.src).or_default().push(e);
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut queue = VecDeque::new();
    seen.insert(root);
    queue.push_back(root);
    let mut used_edges: BTreeSet<&crate::model::Edge> = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        for e in adj.get(id).into_iter().flatten() {
            used_edges.insert(e);
            if seen.insert(&e.dst) {
                queue.push_back(&e.dst);
            }
        }
    }
    let nodes: Vec<&String> = model
        .graph
        .nodes
        .keys()
        .filter(|id| seen.contains(id.as_str()))
        .collect();
    (nodes, used_edges.into_iter().collect())
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const CSS: &str = "body{font-family:system-ui,sans-serif;margin:2rem;background:#fafafa;color:#111}\
h1{font-size:1.4rem}h2{font-size:1.05rem;margin-top:2rem;font-family:monospace}\
.meta{color:#555}.mono{font-family:monospace;font-size:0.85rem}\
.diagram{background:#fff;border:1px solid #ddd;border-radius:6px;padding:0.5rem;overflow-x:auto}\ntable{border-collapse:collapse}\ntd,th{border:1px solid #ccc;padding:2px 8px;text-align:left}";
