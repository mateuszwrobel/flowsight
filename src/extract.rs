//! The provenance-first extractor: route arms -> typed wiring walk -> SQL
//! literals joined against the dbgraph schema. Every edge carries a
//! `file:line` read from source. There are no confidence scores: a call
//! target that cannot be resolved uniquely is an ERROR naming the
//! ambiguity (refuse-to-draw-unproven, specs/investigations/flowsight.md).

use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::{EdgeKind, FlowGraph, NodeKind, Prov};
use crate::source::{DefRef, FnOwner, ImplSite, SourceSet};

/// What went wrong: every variant names the exact ambiguity or stale
/// anchor with file:line, so a red run is actionable.
#[derive(Debug)]
pub enum FlowError {
    Io(String),
    NoRoutes,
    Ambiguous {
        site: Prov,
        what: String,
        candidates: Vec<String>,
    },
    StaleAnchor {
        anchor: String,
        detail: String,
    },
    Config(String),
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowError::Io(m) => write!(f, "io: {m}"),
            FlowError::NoRoutes => write!(f, "no route arms found in the source set"),
            FlowError::Ambiguous { site, what, candidates } => {
                write!(
                    f,
                    "ambiguous {what} at {}:{} — candidates: {}",
                    site.file,
                    site.line,
                    candidates.join(", ")
                )
            }
            FlowError::StaleAnchor { anchor, detail } => {
                write!(f, "stale declared-topology anchor {anchor}: {detail}")
            }
            FlowError::Config(m) => write!(f, "config: {m}"),
        }
    }
}

impl std::error::Error for FlowError {}

/// Input for one analysis run.
pub struct AnalyzeConfig {
    /// Root of the analyzed tree; provenance paths are relative to it.
    pub root: PathBuf,
    /// Crate directories under root (each with a Cargo.toml).
    pub crates: Vec<PathBuf>,
    /// Name of the composition-root struct that types the wires (boot.rs).
    pub app_struct: String,
    /// Table names from the dbgraph `graph.toml`; none means every table
    /// sight is reported unresolved.
    pub schema_tables: Option<BTreeSet<String>>,
    /// Extra walk roots (resolved declared-topology anchors), given as
    /// (file, symbol) and resolved against the source set.
    pub seeds: Vec<(String, String)>,
}

impl Default for AnalyzeConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            crates: Vec::new(),
            app_struct: "App".to_string(),
            schema_tables: None,
            seeds: Vec::new(),
        }
    }
}

/// One call sight found in a body.
#[derive(Debug, Clone)]
enum Call {
    /// `owner.field.method(` where owner is app, self, or a proven alias.
    Field {
        owner: String,
        field: String,
        name: String,
        offset: usize,
    },
    /// `Type::method(`
    Type { ty: String, name: String, offset: usize },
    /// `path::to::module::name(`
    Path { path: String, offset: usize },
    /// `name(` — same-file, then use-imports, then unique in crate.
    Bare { name: String, offset: usize },
}

static RE_ARM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\(\s*"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)"\s*,\s*\[([^\]]*)\]\s*\)\s*=>"#).unwrap()
});
static RE_SEG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([a-z0-9A-Z_/-]+)"|([a-z_][A-Za-z0-9_]*)|\.\."#).unwrap());
static RE_CALL_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap());
static RE_DIRECT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([a-z_][a-z0-9_]*)\s*\(").unwrap());
static RE_CHAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(app|self|[a-z_][a-z0-9_]*)(?:\.([a-z_][a-z0-9_]*))?(?:\.\w+\(\))*$").unwrap());
static RE_ALIAS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet\s+([a-z_][a-z0-9_]*)\s*=\s*(app|self)\s*\.\s*([a-z_][a-z0-9_]*)").unwrap()
});
static RE_METHOD_ALIAS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet\s+([a-z_][a-z0-9_]*)\s*=\s*self\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)").unwrap()
});
static RE_SQL_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(SELECT|INSERT\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE)\b").unwrap()
});
static RE_SQL_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:INSERT\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM|FROM|JOIN)\s+([a-z_][a-z0-9_]*)").unwrap()
});

/// Methods that resolve to smart-pointer/std behaviour, not project code.
const SKIP_METHODS: &[&str] = &[
    "as_bytes", "as_deref", "as_mut", "as_ptr", "as_ref", "borrow", "borrow_mut", "capacity",
    "clone", "cloned", "collect", "copied", "contains", "contains_key", "deref", "deref_mut",
    "display", "downcast_ref", "drop", "ends_with", "entry", "eq", "err", "expect", "filter",
    "filter_map", "flush", "fmt", "from", "get", "insert", "into", "into_inner", "is_empty",
    "is_err", "is_none", "is_ok", "is_some", "iter", "iter_mut", "join", "keys", "len", "lock",
    "map", "map_or", "map_or_else", "map_err", "next", "ok", "ok_or", "ok_or_else", "or",
    "or_else", "pop", "push", "read", "read_to_string", "recv", "remove", "send", "skip",
    "starts_with", "strip_prefix", "take", "to_ascii_lowercase", "to_owned", "to_path_buf",
    "to_string", "to_string_lossy", "to_vec", "trim", "trim_end", "trim_start", "try_into",
    "try_lock", "type_name", "unwrap", "unwrap_or", "unwrap_or_default", "unwrap_or_else",
    "values", "write", "write_all",
];

/// Type names whose methods never enter the flow graph.
const STD_TYPES: &[&str] = &[
    "Any", "AtomicBool", "AtomicU64", "AtomicUsize", "BTreeMap", "BTreeSet", "Box", "Builder",
    "Cell", "Channel", "Duration", "File", "Formatter", "HashMap", "HashSet", "Instant", "Json",
    "Mutex", "Option", "Path", "PathBuf", "Rc", "Receiver", "Ref", "RefCell", "Result", "RwLock",
    "Sender", "String", "TcpListener", "TcpStream", "UdsStream", "UnixStream", "Vec", "VecDeque",
    "Value", "bool", "char", "f64", "i32", "i64", "str", "u32", "u64", "usize",
];

const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "do", "dyn", "else", "enum",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe",
    "use", "where", "while", "Some", "None", "Ok", "Err",
];

const SQL_NOISE: &[&str] = &[
    "select", "set", "where", "values", "sqlite_master", "pragma", "into", "rowid",
];

/// Table names declared by CREATE TABLE statements in the analyzed set.
/// This is the phase-1 stand-in for a dbgraph `graph.toml`: the schema is
/// read from the code that creates it, never guessed.
#[must_use]
pub fn derive_schema_tables(set: &SourceSet) -> BTreeSet<String> {
    static RE_CREATE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)").unwrap()
    });
    let mut out = BTreeSet::new();
    for f in &set.files {
        for (s, e) in &f.strings {
            for cap in RE_CREATE.captures_iter(&f.text[*s..*e]) {
                out.insert(cap.get(1).unwrap().as_str().to_string());
            }
        }
    }
    out
}

fn is_std_type(t: &str) -> bool {
    STD_TYPES.contains(&t)
}

/// One walk item: either a definition site or an inline body slice (a
/// route arm RHS) inside a file, tagged with the caller node id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Item {
    Def(DefRef),
    Body {
        fi: usize,
        start: usize,
        end: usize,
        caller: String,
    },
}

/// A route-arm sight: (route node id, file index, rhs byte range).
type RouteHit = (String, usize, (usize, usize));

/// Run the analysis; returns the index (for later topology checks) and
/// the flow graph.
pub fn analyze(cfg: &AnalyzeConfig) -> Result<(SourceSet, FlowGraph), FlowError> {
    let set = SourceSet::build(&cfg.root, &cfg.crates).map_err(FlowError::Io)?;
    let mut x = Extractor {
        set: &set,
        cfg,
        graph: FlowGraph::default(),
        aliases: Vec::new(),
        self_ty: None,
        pending: Vec::new(),
    };
    x.run()?;
    let graph = std::mem::take(&mut x.graph);
    drop(x);
    Ok((set, graph))
}

struct Extractor<'a> {
    set: &'a SourceSet,
    cfg: &'a AnalyzeConfig,
    graph: FlowGraph,
    aliases: Vec<(String, Binding)>, // binding name -> what it points at
    self_ty: Option<String>,
    pending: Vec<DefRef>,
}

impl Extractor<'_> {
    fn run(&mut self) -> Result<(), FlowError> {
        let set = self.set;
        let routes = self.routes()?;
        if routes.is_empty() {
            return Err(FlowError::NoRoutes);
        }
        let mut work: VecDeque<Item> = VecDeque::new();
        for (route_id, fi, rhs) in routes {
            let f = &set.files[fi];
            let arm_prov = Prov::new(f.path.clone(), f.line_of(rhs.0));
            let rhs_text = f.masked[rhs.0..rhs.1].to_string();
            if let Some(name) = direct_call_name(&rhs_text) {
                let off = rhs.0 + rhs_text.find(&name).unwrap_or(0);
                match self.resolve_bare_call(fi, &name, &Prov::new(f.path.clone(), f.line_of(off)))? {
                    Some(defs) => {
                        for d in defs {
                            let id = self.set.def_id(d);
                            self.node_of(d);
                            self.graph.edge(route_id.clone(), id, EdgeKind::Route, arm_prov.clone());
                            work.push_back(Item::Def(d));
                        }
                    }
                    None => work.push_back(Item::Body {
                        fi,
                        start: rhs.0,
                        end: rhs.1,
                        caller: route_id.clone(),
                    }),
                }
                continue;
            }
            work.push_back(Item::Body {
                fi,
                start: rhs.0,
                end: rhs.1,
                caller: route_id,
            });
        }
        for (file, sym) in &self.cfg.seeds {
            match self.seed_def(file, sym) {
                Some(d) => {
                    self.node_of(d);
                    work.push_back(Item::Def(d));
                }
                None => self
                    .graph
                    .unresolved(format!("unresolved: seed anchor {file}:{sym} has no fn definition to walk")),
            }
        }
        let mut done: BTreeSet<Item> = BTreeSet::new();
        while let Some(item) = work.pop_front() {
            if !done.insert(item.clone()) {
                continue;
            }
            match item {
                Item::Def(d) => {
                    let f = &set.files[d.0];
                    let (start, end) = match &f.fns[d.1].body {
                        Some(b) => *b,
                        None => continue,
                    };
                    let caller = self.set.def_id(d);
                    self.sql_scan_range(&caller, d.0, start, end);
                    let owner_ty = match &f.fns[d.1].owner {
                        FnOwner::Impl(t) | FnOwner::Trait(t) => Some(t.clone()),
                        FnOwner::Free => None,
                    };
                    let sites = call_sites(&f.masked, start, end);
                    self.aliases = self.bindings(&f.masked, start, end, owner_ty.as_deref());
                    self.self_ty = owner_ty;
                    for c in &sites {
                        self.handle_call(d.0, &caller, c)?;
                    }
                }
                Item::Body {
                    fi,
                    start,
                    end,
                    caller,
                } => {
                    let f = &set.files[fi];
                    self.sql_scan_range(&caller, fi, start, end);
                    let sites = call_sites(&f.masked, start, end);
                    self.aliases = self.bindings(&f.masked, start, end, None);
                    self.self_ty = None;
                    for c in &sites {
                        self.handle_call(fi, &caller, c)?;
                    }
                }
            }
            for d in self.pending.drain(..) {
                work.push_back(Item::Def(d));
            }
        }
        Ok(())
    }

    /// Route arms across all files; returns (route node id, file, rhs range).
    /// The arm pattern is matched in the ORIGINAL text because the verb and
    /// path segments are string literals (blanked in the masked copy); a
    /// match only counts when its structural characters — the opening `(`
    /// and the `=>` — are unmasked at the same offsets, which filters out
    /// arms that live only inside comments or string literals.
    fn routes(&mut self) -> Result<Vec<RouteHit>, FlowError> {
        let set = self.set;
        let mut out = Vec::new();
        for fi in 0..set.files.len() {
            let f = &set.files[fi];
            let mb = f.masked.as_bytes();
            let arms: Vec<_> = RE_ARM.captures_iter(&f.text).collect();
            for cap in arms {
                let m = cap.get(0).unwrap();
                if mb.get(m.start()).copied() != Some(b'(') {
                    continue;
                }
                if mb.get(m.end().saturating_sub(1)).copied() != Some(b'>') {
                    continue;
                }
                if f.in_test_region(m.start()) {
                    continue;
                }
                let verb = cap.get(1).unwrap().as_str();
                let segs_range = cap.get(2).unwrap();
                let path = route_path(&f.text[segs_range.start()..segs_range.end()]);
                let id = format!("ROUTE:{verb} {path}");
                let prov = Prov::new(f.path.clone(), f.line_of(m.start()));
                self.graph
                    .node(id.clone(), NodeKind::Route, format!("{verb} {path}"), Some(prov));
                let rhs_start = m.end();
                let rhs_end = rhs_end(&f.masked, rhs_start);
                out.push((id, fi, (rhs_start, rhs_end)));
            }
        }
        Ok(out)
    }

    /// Resolve an anchor (file, symbol) to a fn definition in that file.
    fn seed_def(&self, file: &str, sym: &str) -> Option<DefRef> {
        let fi = self.set.files.iter().position(|f| f.path == file)?;
        let (oi, _) = self.set.files[fi]
            .fns
            .iter()
            .enumerate()
            .find(|(_, o)| o.name == sym && !o.in_test_region)?;
        Some((fi, oi))
    }

    fn node_of(&mut self, d: DefRef) {
        let id = self.set.def_id(d);
        let prov = Prov::new(self.set.def_file(d).path.clone(), self.set.def_line(d));
        self.graph.node(id.clone(), NodeKind::Fn, label_of(&id), Some(prov));
    }

    fn handle_call(&mut self, fi: usize, caller: &str, c: &Call) -> Result<(), FlowError> {
        let set = self.set;
        let file = &set.files[fi];
        let site = |off: usize| Prov::new(file.path.clone(), file.line_of(off));
        match c {
            Call::Field { owner, field, name, offset } => {
                if SKIP_METHODS.contains(&name.as_str()) {
                    return Ok(());
                }
                let ty_expr = if field.is_empty() {
                    self.receiver_type(owner)
                } else {
                    self.field_type(owner, field)
                };
                let Some(ty_expr) = ty_expr else {
                    return Ok(()); // plain data field or unknown: no edge invented
                };
                let off = *offset;
                self.emit_field_call(caller, &ty_expr, name, site(off))?;
            }
            Call::Type { ty, name, offset } => {
                if SKIP_METHODS.contains(&name.as_str())
                    || name.starts_with(|c: char| c.is_uppercase())
                {
                    // An all-uppercase target is an enum-variant
                    // constructor, not a call to code we index.
                    return Ok(());
                }
                let off = *offset;
                self.emit_field_call(caller, ty, name, site(off))?;
            }
            Call::Path { path, offset } => {
                let off = *offset;
                if let Some(def) = self.set.resolve_path(fi, path) {
                    let id = self.set.def_id(def);
                    self.node_of(def);
                    self.graph.edge(caller.to_string(), id, EdgeKind::Call, site(off));
                    self.pending.push(def);
                }
            }
            Call::Bare { name, offset } => {
                let off = *offset;
                if KEYWORDS.contains(&name.as_str()) || SKIP_METHODS.contains(&name.as_str()) {
                    return Ok(());
                }
                if let Some(defs) = self.resolve_bare_call(fi, name, &site(off))? {
                    for def in defs {
                        let id = self.set.def_id(def);
                        self.node_of(def);
                        self.graph.edge(caller.to_string(), id, EdgeKind::Call, site(off));
                        self.pending.push(def);
                    }
                }
            }
        }
        Ok(())
    }

    /// The type a bare receiver names: the App struct, the current impl
    /// owner, or whatever a local binding resolves to.
    fn receiver_type(&self, owner: &str) -> Option<String> {
        if owner == "app" {
            return Some(self.cfg.app_struct.clone());
        }
        if owner == "self" {
            return self.self_ty.clone();
        }
        let (_, b) = self.aliases.iter().find(|(a, _)| a == owner)?;
        match b {
            Binding::Ty(t) => Some(t.clone()),
            Binding::Field(own, fld) => {
                if own == "app" {
                    self.set.struct_field(&self.cfg.app_struct, fld).map(|f| f.ty.clone())
                } else {
                    self.self_ty
                        .as_ref()
                        .and_then(|t| self.set.struct_field(t, fld).map(|f| f.ty.clone()))
                }
            }
        }
    }

    fn field_type(&self, owner: &str, field: &str) -> Option<String> {
        if owner == "app" {
            return self.set.struct_field(&self.cfg.app_struct, field).map(|f| f.ty.clone());
        }
        if owner == "self" {
            return self
                .self_ty
                .as_ref()
                .and_then(|t| self.set.struct_field(t, field).map(|f| f.ty.clone()));
        }
        let (_, b) = self.aliases.iter().find(|(a, _)| a == owner)?;
        match b {
            Binding::Ty(t) => Some(t.clone()),
            Binding::Field(own, fld) => {
                if own == "app" {
                    self.set.struct_field(&self.cfg.app_struct, fld).map(|f| f.ty.clone())
                } else {
                    self.self_ty
                        .as_ref()
                        .and_then(|t| self.set.struct_field(t, fld).map(|f| f.ty.clone()))
                }
            }
        }
    }

    /// The body's local bindings: field aliases (`let x = app.f`) and
    /// zero-arg method bindings (`let x = self.m()`), the latter typed by
    /// the method's declared return type.
    fn bindings(
        &self,
        masked: &str,
        start: usize,
        end: usize,
        owner_ty: Option<&str>,
    ) -> Vec<(String, Binding)> {
        let s = &masked[start..end];
        let mut out: Vec<(String, Binding)> = RE_ALIAS
            .captures_iter(s)
            .map(|c| {
                (
                    c.get(1).unwrap().as_str().to_string(),
                    Binding::Field(
                        c.get(2).unwrap().as_str().to_string(),
                        c.get(3).unwrap().as_str().to_string(),
                    ),
                )
            })
            .collect();
        if let Some(t) = owner_ty {
            for c in RE_METHOD_ALIAS.captures_iter(s) {
                let var = c.get(1).unwrap().as_str().to_string();
                let m = c.get(2).unwrap().as_str();
                if out.iter().any(|(a, _)| *a == var) {
                    continue;
                }
                if let Some(d) = self.set.method_defs(t, m).first().copied()
                    && let Some(ret) = self.set.fn_ret(d)
                {
                    out.push((var, Binding::Ty(ret)));
                }
            }
        }
        out
    }

    fn resolve_bare_call(
        &self,
        fi: usize,
        name: &str,
        site: &Prov,
    ) -> Result<Option<Vec<DefRef>>, FlowError> {
        let defs = self.set.resolve_bare(fi, name);
        match defs.len() {
            0 => Ok(None),
            1 => Ok(Some(defs)),
            _ => Err(FlowError::Ambiguous {
                site: site.clone(),
                what: format!("call of `{name}`"),
                candidates: defs
                    .iter()
                    .map(|d| format!("{}:{}", self.set.def_file(*d).path, self.set.def_line(*d)))
                    .collect(),
            }),
        }
    }

    /// Emit an edge for a call through a typed expression.
    fn emit_field_call(&mut self, caller: &str, ty_expr: &str, name: &str, site: Prov) -> Result<(), FlowError> {
        let stripped = strip_wrappers(ty_expr);
        if let Some(tr) = dyn_trait(&stripped) {
            return self.emit_trait_call(caller, &tr, name, site);
        }
        let ty = match last_ident(&stripped) {
            Some(t) => t,
            None => return Ok(()),
        };
        if is_std_type(&ty) {
            return Ok(());
        }
        if self.set.is_trait(&ty) {
            return self.emit_trait_call(caller, &ty, name, site);
        }
        let defs = self.set.method_defs(&ty, name);
        if defs.is_empty() {
            if !self.set.has_struct(&ty) && !self.set.is_trait(&ty) {
                // The type lives outside the analyzed set: the edge is
                // absent (not ambiguous), so nothing is invented here.
                return Ok(());
            }
            self.graph.unresolved(format!(
                "unresolved: `{ty}::{name}` has no definition in scope at {}:{}",
                site.file, site.line
            ));
            return Ok(());
        }
        let id = self.set.def_id(defs[0]);
        self.graph
            .node(id.clone(), NodeKind::Fn, format!("{ty}::{name}"), self.def_prov(defs[0]));
        self.graph.edge(caller.to_string(), id, EdgeKind::Call, site);
        self.pending.extend(defs.iter().copied());
        Ok(())
    }

    fn emit_trait_call(&mut self, caller: &str, tr: &str, name: &str, site: Prov) -> Result<(), FlowError> {
        let trait_defs = self.set.method_defs(tr, name);
        if trait_defs.is_empty() {
            self.graph.unresolved(format!(
                "unresolved: trait `{tr}` has no method `{name}` visible at {}:{}",
                site.file, site.line
            ));
            return Ok(());
        }
        let trait_id = self.set.def_id(trait_defs[0]);
        self.graph
            .node(trait_id.clone(), NodeKind::Fn, format!("{tr}::{name}"), self.def_prov(trait_defs[0]));
        self.graph.edge(caller.to_string(), trait_id.clone(), EdgeKind::Call, site.clone());
        let sites = self.set.trait_impl_sites(tr);
        match sites.len() {
            0 => {
                self.graph.unresolved(format!(
                    "unresolved: no impl of `{tr}` in scope for the call at {}:{}",
                    site.file, site.line
                ));
            }
            1 => {
                let impl_site = &sites[0];
                let defs = self.set.method_defs(&impl_site.ty, name);
                if defs.is_empty() {
                    self.graph.unresolved(format!(
                        "unresolved: impl {} for {tr} at {}:{} lacks `{name}`",
                        impl_site.ty, impl_site.path, impl_site.line
                    ));
                    return Ok(());
                }
                let impl_id = self.set.def_id(defs[0]);
                self.graph.node(
                    impl_id.clone(),
                    NodeKind::Fn,
                    format!("{}::{name}", impl_site.ty),
                    self.def_prov(defs[0]),
                );
                self.graph.edge(
                    trait_id,
                    impl_id,
                    EdgeKind::Dispatch,
                    Prov::new(impl_site.path.clone(), impl_site.line),
                );
                self.pending.extend(defs.iter().copied());
            }
            _ => {
                // Several impls exist. The dyn object's construction site
                // names the runtime target: if exactly one candidate impl
                // appears at a construction, the hop is proven. Otherwise
                // the dispatch stays ambiguous.
                let ctors = self.set.construction_sites(tr);
                let mut matched: Option<ImplSite> = None;
                let mut first_prov: Option<Prov> = None;
                let mut conflict = false;
                for (path, line, cpath) in &ctors {
                    let mut segs: Vec<&str> = cpath.split("::").filter(|s| !s.is_empty()).collect();
                    if segs.last().copied() == Some("new") {
                        segs.pop();
                    }
                    let ctor = segs.last().copied().unwrap_or("");
                    if let Some(site) = sites.iter().find(|s| s.ty == ctor) {
                        match &matched {
                            None => {
                                matched = Some(site.clone());
                                first_prov = Some(Prov::new(path.clone(), *line));
                            }
                            Some(prev) if prev == site => {}
                            Some(_) => conflict = true,
                        }
                    }
                }
                let Some(site) = matched.filter(|_| !conflict) else {
                    return Err(FlowError::Ambiguous {
                        site,
                        what: format!("dispatch of `{tr}::{name}`"),
                        candidates: sites
                            .iter()
                            .map(|s| format!("impl {} for {tr} at {}:{}", s.ty, s.path, s.line))
                            .collect(),
                    });
                };
                let defs = self.set.method_defs(&site.ty, name);
                if defs.is_empty() {
                    self.graph.unresolved(format!(
                        "unresolved: impl {} for {tr} at {}:{} lacks `{name}`",
                        site.ty, site.path, site.line
                    ));
                    return Ok(());
                }
                let impl_id = self.set.def_id(defs[0]);
                self.graph.node(
                    impl_id.clone(),
                    NodeKind::Fn,
                    format!("{}::{name}", site.ty),
                    self.def_prov(defs[0]),
                );
                self.graph.edge(
                    trait_id,
                    impl_id,
                    EdgeKind::Dispatch,
                    first_prov.unwrap_or_else(|| Prov::new(site.path.clone(), site.line)),
                );
                self.pending.extend(defs.iter().copied());
            }
        }
        Ok(())
    }

    fn def_prov(&self, d: DefRef) -> Option<Prov> {
        Some(Prov::new(self.set.def_file(d).path.clone(), self.set.def_line(d)))
    }

    fn sql_scan_range(&mut self, caller: &str, fi: usize, start: usize, end: usize) {
        let set = self.set;
        let f = &set.files[fi];
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for (s, e) in &f.strings {
            if *e <= start || *s >= end {
                continue;
            }
            let lit = &f.text[*s..*e];
            if !RE_SQL_CONTEXT.is_match(lit) {
                continue;
            }
            let line = f.line_of(*s);
            for cap in RE_SQL_TABLE.captures_iter(lit) {
                let t = cap.get(1).unwrap().as_str();
                if SQL_NOISE.contains(&t) {
                    continue;
                }
                if !seen.insert(t.to_string()) {
                    continue;
                }
                match &self.cfg.schema_tables {
                    None => {
                        self.graph.unresolved(format!(
                            "unresolved: `{caller}` mentions table `{t}` at {}:{line} but no schema was declared",
                            f.path
                        ));
                    }
                    Some(decl) => {
                        if decl.contains(t) {
                            let id = format!("TABLE:{t}");
                            self.graph.node(id.clone(), NodeKind::Table, t, None);
                            self.graph
                                .edge(caller.to_string(), id, EdgeKind::Sql, Prov::new(f.path.clone(), line));
                        } else {
                            self.graph.unresolved(format!(
                                "unresolved: `{caller}` mentions table `{t}` at {}:{line} which is not in the declared schema",
                                f.path
                            ));
                        }
                    }
                }
            }
        }
    }
}

/// The RHS of a route arm is a direct handler call when it starts with
/// `name(`.
fn direct_call_name(rhs: &str) -> Option<String> {
    let t = rhs.trim_start();
    RE_DIRECT.captures(t).map(|c| c.get(1).unwrap().as_str().to_string())
}

fn route_path(segs: &str) -> String {
    let mut parts = Vec::new();
    for cap in RE_SEG.captures_iter(segs) {
        if let Some(lit) = cap.get(1) {
            parts.push(lit.as_str().to_string());
        } else if let Some(ident) = cap.get(2) {
            if !["as", "str", "slice", "rest"].contains(&ident.as_str()) {
                parts.push(format!("{{{}}}", ident.as_str()));
            }
        } else {
            parts.push("…".to_string());
        }
    }
    let mut path = String::new();
    for p in parts {
        path.push('/');
        path.push_str(&p);
    }
    if path.is_empty() {
        path.push('/');
    }
    path
}

/// End of a match arm: the next top-level `,` or the match-block `}`.
fn rhs_end(masked: &str, from: usize) -> usize {
    let bytes = masked.as_bytes();
    let mut depth = 0i32;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => return i,
            b'}' if depth == 0 => return i,
            b'}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Collect every call sight in a body range, classifying each by the text
/// left of the call-name token.
fn call_sites(masked: &str, start: usize, end: usize) -> Vec<Call> {
    let mut out = Vec::new();
    let bytes = masked.as_bytes();
    for cap in RE_CALL_NAME.captures_iter(&masked[start..end]) {
        let m = cap.get(0).unwrap();
        let name = cap.get(1).unwrap().as_str().to_string();
        let off = start + m.start();
        let prev = if off == 0 { b' ' } else { bytes[off - 1] };
        if (prev as char).is_alphanumeric() || prev == b'_' || prev == b'#' {
            continue;
        }
        if prev == b':' {
            // Part of a `::` chain: collect the chain to the left.
            let chain = chain_left(bytes, off);
            if chain.is_empty() {
                continue;
            }
            let mut segs = chain;
            segs.push(name.clone());
            let starts_upper = |s: &str| s.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
            if segs.len() == 2 && starts_upper(&segs[0]) {
                out.push(Call::Type {
                    ty: segs[0].clone(),
                    name: name.clone(),
                    offset: off,
                });
                continue;
            }
            // Path call: prefer the full chain; resolution may still find
            // nothing if the path leaves the analyzed set.
            out.push(Call::Path {
                path: segs.join("::"),
                offset: off,
            });
            continue;
        }
        if prev == b'.' {
            if KEYWORDS.contains(&name.as_str()) {
                continue;
            }
            let recv = receiver_left(bytes, off);
            if let Some(cap) = RE_CHAIN.captures(&recv) {
                let owner = cap.get(1).unwrap().as_str().to_string();
                let field = cap
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                out.push(Call::Field {
                    owner,
                    field,
                    name: name.clone(),
                    offset: off,
                });
            }
            continue;
        }
        out.push(Call::Bare { name, offset: off });
    }
    out
}

/// `a::b::` left of the colon-run at `off` -> ["a", "b"].
fn chain_left(bytes: &[u8], off: usize) -> Vec<String> {
    let mut i = off;
    while i >= 2 && bytes[i - 1] == b':' && bytes[i - 2] == b':' {
        i -= 2;
    }
    let mut segs = Vec::new();
    loop {
        let mut j = i;
        while j > 0 && ((bytes[j - 1] as char).is_alphanumeric() || bytes[j - 1] == b'_') {
            j -= 1;
        }
        if j == i {
            break;
        }
        segs.insert(0, String::from_utf8_lossy(&bytes[j..i]).to_string());
        i = j;
        if i >= 2 && bytes[i - 1] == b':' && bytes[i - 2] == b':' {
            i -= 2;
            continue;
        }
        break;
    }
    segs
}

/// The receiver text before `.` at the call: `app.teams` or, past one
/// balanced `(...)`, the field access in front of it (`self.board.lock()`).
fn receiver_left(bytes: &[u8], off: usize) -> String {
    let mut i = off;
    while i > 0 && (bytes[i - 1] as char).is_whitespace() {
        i -= 1;
    }
    if i == 0 || bytes[i - 1] != b'.' {
        return String::new();
    }
    let dot = i - 1;
    if dot > 0
        && bytes[dot - 1] == b')'
        && let Some(open) = skip_parens_left(bytes, dot - 1)
    {
        let mut e = open;
        while e > 0 && ((bytes[e - 1] as char).is_alphanumeric() || bytes[e - 1] == b'_') {
            e -= 1;
        }
        if e == 0 || bytes[e - 1] != b'.' {
            return String::new();
        }
        let mut s = receiver_left(bytes, e);
        if s.is_empty() {
            return String::new();
        }
        s.push('.');
        s.push_str(masked_slice(bytes, e, open));
        s.push_str("()");
        s
    } else {
        let mut e = dot;
        while e > 0
            && ((bytes[e - 1] as char).is_alphanumeric()
                || bytes[e - 1] == b'_'
                || bytes[e - 1] == b'.')
        {
            e -= 1;
        }
        masked_slice(bytes, e, dot).to_string()
    }
}

fn masked_slice(bytes: &[u8], a: usize, b: usize) -> &str {
    std::str::from_utf8(&bytes[a..b]).unwrap_or("")
}

fn skip_parens_left(bytes: &[u8], close_at: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = close_at as isize;
    while i >= 0 {
        match bytes[i as usize] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i as usize);
                }
            }
            _ => {}
        }
        i -= 1;
    }
    None
}

/// What a local binding is known to point at: a struct field (owner +
/// field) or the declared return type of a zero-arg method call.
#[derive(Debug, Clone)]
enum Binding {
    Field(String, String),
    Ty(String),
}

/// Strip smart-pointer and option wrappers: `Arc<Mutex<dyn Board>>` ->
/// `dyn Board`, `Arc<SqliteRegistry>` -> `SqliteRegistry`.
fn strip_wrappers(ty: &str) -> String {
    let mut t = ty.trim().trim_start_matches('&').trim_start().to_string();
    let wrappers = [
        "Arc<",
        "Box<",
        "Rc<",
        "Mutex<",
        "RefCell<",
        "Cell<",
        "Option<",
        "MutexGuard<",
        "RwLockReadGuard<",
        "RwLockWriteGuard<",
    ];
    loop {
        let mut next = None;
        if t.starts_with("&'") || t.starts_with("&mut ") || t.starts_with('&') {
            let r = t.trim_start_matches('&');
            let r = r.trim_start_matches("mut ").trim_start_matches("'static").trim_start();
            next = Some(r.to_string());
        }
        if next.is_none() {
            for w in wrappers {
                if let Some(rest) = t.strip_prefix(w)
                    && let Some(inner) = rest.strip_suffix('>')
                {
                    next = Some(inner.trim().to_string());
                    break;
                }
            }
        }
        match next {
            Some(n) if n != t => t = n,
            _ => return t,
        }
    }
}

fn dyn_trait(ty: &str) -> Option<String> {
    let i = ty.find("dyn ")?;
    let rest = &ty[i + 4..];
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(rest[..end].to_string())
}

fn last_ident(ty: &str) -> Option<String> {
    UPPER_IDENT.find_iter(ty).last().map(|m| m.as_str().to_string())
}

static UPPER_IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Z][A-Za-z0-9_]*").unwrap());

fn label_of(id: &str) -> String {
    let parts: Vec<&str> = id.split("::").collect();
    if parts.len() > 2 {
        parts[parts.len() - 2..].join("::")
    } else {
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrappers_strip_to_inner_type() {
        assert_eq!(strip_wrappers("Arc<SqliteRegistry>"), "SqliteRegistry");
        assert_eq!(strip_wrappers("Arc<Mutex<SqliteBoard>>"), "SqliteBoard");
        assert_eq!(strip_wrappers("Arc<dyn Registry>"), "dyn Registry");
        assert_eq!(dyn_trait("dyn Registry").as_deref(), Some("Registry"));
        assert_eq!(dyn_trait("SqliteRegistry"), None);
    }

    #[test]
    fn route_paths() {
        assert_eq!(route_path("\"api\", \"teams\""), "/api/teams");
        assert_eq!(route_path("\"api\", id"), "/api/{id}");
        assert_eq!(route_path(""), "/");
    }

    #[test]
    fn rhs_ends_at_top_level_comma() {
        let m = "handler(app, x),\n        other";
        assert_eq!(rhs_end(m, m.find("handler").unwrap()), 15);
    }

    #[test]
    fn route_arm_regex_needs_unmasked_structural_chars() {
        // The verb literal is blanked in the masked copy, so RE_ARM is run
        // on the original text; the guard is the unmasked `(` and `>`.
        let text = "(\"POST\", [\"api\"]) => handle(app),";
        let (masked, _) = crate::source::mask(text);
        assert!(RE_ARM.is_match(text));
        let m = RE_ARM.find(text).unwrap();
        assert_eq!(masked.as_bytes()[m.start()], b'(');
        assert_eq!(masked.as_bytes()[m.end() - 1], b'>');
        // The same text inside a line comment keeps no structural bytes.
        let commented = format!("// {text}");
        let (cm, _) = crate::source::mask(&commented);
        let m2 = RE_ARM.find(&commented).unwrap();
        assert_eq!(cm.as_bytes()[m2.start()], b' ');
    }
}
