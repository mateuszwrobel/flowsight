//! Source-set discovery and the lexical index over Rust files.
//!
//! Everything here is READ-ONLY over the analyzed tree. Structural facts
//! (function definitions, impl blocks, struct fields, use imports) are read
//! from a comment- and string-masked copy of each file, so prose inside
//! strings or comments can never create a definition. `#[cfg(test)]`
//! regions are excluded: test fixtures are not runtime code, and a test
//! `impl` must never turn a single-impl dispatch into an ambiguity.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

/// Masked copy of a file: comments and string-literal bodies replaced by
/// spaces of the same byte length, newlines preserved. Byte offsets in the
/// masked text equal byte offsets in the original text. Returns the masked
/// text and the byte ranges of string-literal CONTENTS (original text).
pub(crate) fn mask(text: &str) -> (String, Vec<(usize, usize)>) {
    let b = text.as_bytes();
    let mut out = vec![b' '; b.len()];
    let mut strings = Vec::new();
    let mut i = 0usize;
    let mut block_depth = 0usize;
    while i < b.len() {
        let c = b[i];
        let rest = &b[i..];
        if block_depth > 0 {
            if rest.starts_with(b"/*") {
                block_depth += 1;
                i += 2;
                continue;
            }
            if rest.starts_with(b"*/") {
                block_depth -= 1;
                i += 2;
                continue;
            }
            if c == b'\n' {
                out[i] = b'\n';
            }
            i += 1;
            continue;
        }
        if c == b'/' && rest.starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if rest.starts_with(b"/*") {
            block_depth = 1;
            i += 2;
            continue;
        }
        // Raw strings: r"..." / r#"..."# / r##"..."##
        if c == b'r' && i + 1 < b.len() && (b[i + 1] == b'"' || b[i + 1] == b'#') {
            let mut j = i + 1;
            let mut hashes = 0usize;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let content_start = j + 1;
                let needle = format!("\"{}", "#".repeat(hashes));
                let content_end = find_seq(b, content_start, needle.as_bytes()).unwrap_or(b.len());
                out[i] = b'r';
                for k in i + 1..content_end.min(b.len()) {
                    if b[k] == b'\n' {
                        out[k] = b'\n';
                    }
                }
                strings.push((content_start, content_end));
                i = (content_end + needle.len()).min(b.len());
                continue;
            }
            out[i] = c;
            i += 1;
            continue;
        }
        if c == b'"' {
            let start = i + 1;
            let mut j = i + 1;
            while j < b.len() {
                if b[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if b[j] == b'"' {
                    break;
                }
                j += 1;
            }
            for k in i + 1..j.min(b.len()) {
                if b[k] == b'\n' {
                    out[k] = b'\n';
                }
            }
            strings.push((start, j.min(b.len())));
            i = (j + 1).min(b.len());
            continue;
        }
        // Char literals (not lifetimes): 'x' or '\n'; 'a stays a lifetime.
        if c == b'\'' && i + 2 < b.len() {
            let closed = if b[i + 1] == b'\\' {
                i + 3 < b.len() && b[i + 3] == b'\''
            } else {
                b[i + 2] == b'\''
            };
            if closed {
                i += if b[i + 1] == b'\\' { 4 } else { 3 };
                continue;
            }
        }
        if c == b'\n' {
            out[i] = b'\n';
        } else {
            out[i] = c;
        }
        i += 1;
    }
    (
        String::from_utf8(out).unwrap_or_else(|_| text.to_string()),
        strings,
    )
}

fn find_seq(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < from + needle.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

fn find_byte(masked: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    find_seq(masked, from, needle)
}

/// Byte offset just past the balanced close of the block whose `{` is at
/// `open_at`, over masked bytes.
fn block_end(masked: &[u8], open_at: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open_at;
    while i < masked.len() {
        match masked[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Who owns a function definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FnOwner {
    Free,
    Impl(String),
    Trait(String),
}

/// A function/method/trait-method definition site inside one file.
#[derive(Debug, Clone)]
pub struct FnDef {
    pub name: String,
    pub owner: FnOwner,
    /// Offset of the `fn` keyword (the provenance anchor).
    pub offset: usize,
    /// Body range `[open_brace, close_brace)`, if the definition has one.
    pub body: Option<(usize, usize)>,
    pub in_test_region: bool,
}

/// A struct field declaration site.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: String,
    pub offset: usize,
}

/// A parsed file in the source set.
#[derive(Debug)]
pub struct FileIdx {
    pub krate: String,
    /// Module path such as `my_service::http::api` (crate name included).
    pub module: String,
    /// Root-relative path with `/` separators — the provenance spelling.
    pub path: String,
    pub text: String,
    pub masked: String,
    /// Byte ranges of string-literal CONTENTS (original text).
    pub strings: Vec<(usize, usize)>,
    newlines: Vec<usize>,
    pub fns: Vec<FnDef>,
    /// Leaf name -> full import paths (expanded from `use` trees).
    pub uses: BTreeMap<String, Vec<String>>,
    /// Modules imported with `use path::*;`.
    pub globs: Vec<String>,
    test_regions: Vec<(usize, usize)>,
}

impl FileIdx {
    #[must_use]
    pub fn line_of(&self, offset: usize) -> usize {
        self.newlines.partition_point(|nl| *nl < offset) + 1
    }

    fn in_test(&self, offset: usize) -> bool {
        self.test_regions
            .iter()
            .any(|(s, e)| offset >= *s && offset < *e)
    }

    #[must_use]
    pub fn in_test_region(&self, offset: usize) -> bool {
        self.in_test(offset)
    }
}

/// One `impl Trait for Type` sight — the provenance for a dispatch hop.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImplSite {
    pub krate: String,
    pub ty: String,
    pub path: String,
    pub line: usize,
}

/// A definition reference: (file index, fn index).
pub type DefRef = (usize, usize);

/// The indexed, read-only view of all analyzed crates.
#[derive(Debug, Default)]
pub struct SourceSet {
    pub files: Vec<FileIdx>,
    free_by_name: BTreeMap<String, Vec<DefRef>>,
    methods: BTreeMap<(String, String), Vec<DefRef>>,
    trait_impls: BTreeMap<String, Vec<ImplSite>>,
    struct_fields: BTreeMap<String, Vec<Field>>,
    module_files: BTreeMap<String, usize>,
    traits: BTreeSet<String>,
}

static RE_FN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>()]*>)?\s*\(").unwrap());
static RE_IMPL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*(?:#\[[^\]]*\]\s*)*impl(?:<[^{]*?>)?\s*([^{;]*?)\s*\{").unwrap());
static RE_TRAIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap()
});
static RE_STRUCT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)[^;{]*\{")
        .unwrap()
});
static RE_USE_TREE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([^;{]*?)\{([^;]*)\}\s*;").unwrap());
static RE_USE_PLAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;").unwrap()
});
static RE_CFG_TEST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]").unwrap());
static RE_PKG_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*name\s*=\s*"([^"]+)""#).unwrap());
static RE_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)([a-z_][A-Za-z0-9_]*)\s*:\s*(\S.*)").unwrap());

impl SourceSet {
    /// Build the index over the given crate directories (each containing a
    /// `Cargo.toml` with `[package] name`). Files under a `tests` directory
    /// or named `tests.rs` are not read at all.
    pub fn build(root: &Path, crate_dirs: &[PathBuf]) -> Result<Self, String> {
        let mut set = Self::default();
        for dir in crate_dirs {
            let manifest = root.join(dir).join("Cargo.toml");
            let text = fs::read_to_string(&manifest)
                .map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
            let krate = RE_PKG_NAME
                .captures(&text)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| dir.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"));
            let src = root.join(dir).join("src");
            let mut stack = vec![src];
            while let Some(d) = stack.pop() {
                let Ok(rd) = fs::read_dir(&d) else { continue };
                let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
                entries.sort();
                for p in entries {
                    if p.is_dir() {
                        if p.file_name().map(|n| n == "tests" || n == "target").unwrap_or(false) {
                            continue;
                        }
                        stack.push(p);
                        continue;
                    }
                    if p.extension().map(|e| e != "rs").unwrap_or(true) {
                        continue;
                    }
                    if p.file_name().map(|n| n == "tests.rs").unwrap_or(false) {
                        continue;
                    }
                    let text = fs::read_to_string(&p)
                        .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
                    let rel = p
                        .strip_prefix(root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .replace(std::path::MAIN_SEPARATOR, "/");
                    let module = module_path(&krate, &rel);
                    set.files.push(parse_file(krate.clone(), module, rel, text));
                }
            }
        }
        set.build_indexes();
        Ok(set)
    }

    fn build_indexes(&mut self) {
        for fi in 0..self.files.len() {
            let f = &self.files[fi];
            self.module_files.entry(f.module.clone()).or_insert(fi);
            let mb = f.masked.as_bytes();
            // Item regions: impl blocks (owner Impl(ty)) and trait blocks
            // (owner Trait(name)). fn bodies nest inside them.
            let mut regions: Vec<(usize, usize, FnOwner)> = Vec::new();
            for cap in RE_IMPL.captures_iter(&f.masked) {
                let m = cap.get(0).unwrap();
                let head = cap.get(1).map(|x| x.as_str()).unwrap_or("");
                let Some(open) = find_byte(mb, m.start(), b"{") else { continue };
                let Some(end) = block_end(mb, open) else { continue };
                let (_, ty) = split_impl_head(head);
                let Some(ty) = ty else { continue };
                regions.push((open, end, FnOwner::Impl(ty.clone())));
                if let Some(tr) = split_impl_head(head).0
                    && !f.in_test(m.start())
                {
                    self.trait_impls.entry(tr).or_default().push(ImplSite {
                        krate: f.krate.clone(),
                        ty,
                        path: f.path.clone(),
                        line: f.line_of(m.start()),
                    });
                }
            }
            for cap in RE_TRAIT.captures_iter(&f.masked) {
                let m = cap.get(0).unwrap();
                if f.in_test(m.start()) {
                    continue;
                }
                let name = cap.get(1).unwrap().as_str().to_string();
                self.traits.insert(name.clone());
                let Some(open) = find_byte(mb, m.end(), b"{") else { continue };
                let Some(end) = block_end(mb, open) else { continue };
                regions.push((open, end, FnOwner::Trait(name)));
            }
            // Nested-fn detection: an fn whose offset lies inside another
            // fn's body is a local helper; it resolves as a plain call to
            // nothing in our model and is not indexed.
            let mut defs: Vec<(usize, Option<(usize, usize)>)> = Vec::new();
            for cap in RE_FN.captures_iter(&f.masked) {
                let m = cap.get(0).unwrap();
                let body_open = match fn_body_open(mb, m.end()) {
                    Some((open, false)) => block_end(mb, open).map(|e| (open, e)),
                    Some((_, true)) => None,
                    None => None,
                };
                defs.push((m.start(), body_open));
            }
            // RE_FN iteration order matches the source order; do the
            // authoritative attach here. A def whose offset lies inside an
            // earlier def's body is a nested local helper and is dropped.
            let mut pushed: Vec<(usize, usize)> = Vec::new();
            let mut newfns: Vec<FnDef> = Vec::new();
            for (offset, body) in &defs {
                let name_at =
                    find_byte(mb, *offset, b"fn ").map(|o| o + 3).unwrap_or(*offset);
                let name = {
                    let rest = &f.masked[name_at..];
                    let end = rest
                        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .unwrap_or(rest.len());
                    rest[..end].to_string()
                };
                let mut owner = FnOwner::Free;
                let mut width = usize::MAX;
                for (s, e, o) in &regions {
                    if *offset >= *s && *offset < *e && e - s < width {
                        owner = o.clone();
                        width = e - s;
                    }
                }
                let nested = pushed.iter().any(|(bs, be)| *offset > *bs && *offset < *be);
                if nested {
                    continue;
                }
                if let Some((bs, be)) = body {
                    pushed.push((*bs, *be));
                }
                let in_test_region = f.in_test(*offset);
                newfns.push(FnDef {
                    name,
                    owner,
                    offset: *offset,
                    body: *body,
                    in_test_region,
                });
            }
            std::mem::swap(&mut self.files[fi].fns, &mut newfns);
            let file = &self.files[fi];
            let mb = file.masked.as_bytes();
            for (oi, o) in file.fns.iter().enumerate() {
                if o.in_test_region {
                    continue;
                }
                match &o.owner {
                    FnOwner::Free => {
                        self.free_by_name.entry(o.name.clone()).or_default().push((fi, oi));
                    }
                    FnOwner::Impl(t) | FnOwner::Trait(t) => {
                        self.methods.entry((t.clone(), o.name.clone())).or_default().push((fi, oi));
                    }
                }
            }
            for cap in RE_STRUCT.captures_iter(&file.masked) {
                let m = cap.get(0).unwrap();
                if file.in_test(m.start()) {
                    continue;
                }
                let nested = file.fns.iter().any(|o: &FnDef| match &o.body {
                    Some((s, e)) => m.start() > *s && m.start() < *e,
                    None => false,
                });
                if nested {
                    continue;
                }
                let name = cap.get(1).unwrap().as_str().to_string();
                let Some(open) = find_byte(mb, m.start(), b"{") else { continue };
                let Some(end) = block_end(mb, open) else { continue };
                let fields = parse_fields(file, open, end);
                self.struct_fields.entry(name).or_default().extend(fields);
            }
        }
    }

    #[must_use]
    pub fn def_file(&self, d: DefRef) -> &FileIdx {
        &self.files[d.0]
    }

    #[must_use]
    pub fn def_line(&self, d: DefRef) -> usize {
        self.files[d.0].line_of(self.files[d.0].fns[d.1].offset)
    }

    /// Node spelling for a definition: `crate::module::name` for free fns,
    /// `crate::Type::method` for methods and trait methods.
    #[must_use]
    pub fn def_id(&self, d: DefRef) -> String {
        let f = &self.files[d.0];
        let o = &f.fns[d.1];
        match &o.owner {
            FnOwner::Free => format!("{}::{}", f.module, o.name),
            FnOwner::Impl(t) | FnOwner::Trait(t) => format!("{}::{}::{}", f.krate, t, o.name),
        }
    }

    #[must_use]
    pub fn free_defs(&self, name: &str) -> Vec<DefRef> {
        self.free_by_name.get(name).cloned().unwrap_or_default()
    }

    #[must_use]
    pub fn method_defs(&self, ty: &str, name: &str) -> Vec<DefRef> {
        self.methods
            .get(&(ty.to_string(), name.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// All in-scope, non-test `impl <Trait> for <Type>` sights.
    #[must_use]
    pub fn trait_impl_sites(&self, trait_: &str) -> Vec<ImplSite> {
        self.trait_impls.get(trait_).cloned().unwrap_or_default()
    }

    /// The declared return type of a definition, read from the signature
    /// between the parameter list and the body: `MutexGuard<'_, X>` ->
    /// `Some("MutexGuard<'_, X>")`. `None` for `fn` without `->`.
    #[must_use]
    pub fn fn_ret(&self, d: DefRef) -> Option<String> {
        let f = &self.files[d.0];
        let mb = f.masked.as_bytes();
        let open = find_byte(mb, f.fns[d.1].offset, b"(")?;
        let mut i = open;
        let mut depth = 0i32;
        while i < mb.len() {
            match mb[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let limit = f.fns[d.1].body.map_or(f.masked.len(), |b| b.0);
        let i = i + 1;
        if i >= limit {
            return None;
        }
        let tail = &f.masked[i..limit];
        let arrow = tail.find("->")?;
        let ty_part = &tail[arrow + 2..];
        let mut d2 = 0i32;
        let mut end = ty_part.len();
        let tb = ty_part.as_bytes();
        for j in 0..tb.len() {
            match tb[j] {
                b'(' | b'<' | b'[' => d2 += 1,
                b')' | b'>' | b']' => d2 -= 1,
                b'{' | b';' if d2 <= 0 => {
                    end = j;
                    break;
                }
                _ => {}
            }
            if d2 <= 0 && ty_part[j..].starts_with("where ") {
                end = j;
                break;
            }
        }
        let t = ty_part[..end].trim().to_string();
        (!t.is_empty()).then_some(t)
    }

    /// Where `dyn Trait` values are CONSTRUCTED: sites of
    /// `dyn Trait ... = Arc|Box|Rc::new(<path>...)` in non-test code, as
    /// (file, line, constructor path), sorted. This is what disambiguates
    /// a dispatch hop when the trait has several impls: the runtime target
    /// is the type the constructor names.
    #[must_use]
    pub fn construction_sites(&self, trait_: &str) -> Vec<(String, usize, String)> {
        if trait_.is_empty() || !trait_.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Vec::new();
        }
        let re = Regex::new(&format!(
            r"dyn\s+{trait_}\s*>\s*=\s*(?:Arc|Box|Rc)::new\(\s*([A-Za-z_][A-Za-z0-9_:]*)"
        ))
        .expect("identifier-only pattern");
        let mut out = Vec::new();
        for f in &self.files {
            for cap in re.captures_iter(&f.masked) {
                let m = cap.get(0).unwrap();
                if f.in_test_region(m.start()) {
                    continue;
                }
                out.push((
                    f.path.clone(),
                    f.line_of(m.start()),
                    cap.get(1).unwrap().as_str().to_string(),
                ));
            }
        }
        out.sort();
        out
    }

    #[must_use]
    pub fn is_trait(&self, name: &str) -> bool {
        self.traits.contains(name)
    }

    #[must_use]
    pub fn struct_field(&self, ty: &str, name: &str) -> Option<&Field> {
        self.struct_fields
            .get(ty)
            .and_then(|fs| fs.iter().find(|f| f.name == name))
    }

    /// Resolve `name` as seen from file `fi`: same-file free fns first,
    /// then `use` imports (following re-exports), then a unique same-crate
    /// free fn. Returns every candidate; the caller decides whether
    /// multiple candidates are an ambiguity.
    pub fn resolve_bare(&self, fi: usize, name: &str) -> Vec<DefRef> {
        let mut out: Vec<DefRef> = self
            .free_defs(name)
            .into_iter()
            .filter(|d| d.0 == fi)
            .collect();
        if !out.is_empty() {
            return out;
        }
        if let Some(paths) = self.files[fi].uses.get(name) {
            for p in paths {
                if let Some(d) = self.resolve_path(fi, p) {
                    out.push(d);
                }
            }
            if !out.is_empty() {
                return dedup_refs(&out);
            }
        }
        for g in &self.files[fi].globs {
            for cand in self.module_candidates(fi, g) {
                if let Some(&mfi) = self.module_files.get(&cand) {
                    let hits: Vec<DefRef> = self
                        .free_defs(name)
                        .into_iter()
                        .filter(|d| d.0 == mfi)
                        .collect();
                    if !hits.is_empty() {
                        return dedup_refs(&hits);
                    }
                }
            }
        }
        let krate = self.files[fi].krate.clone();
        out.extend(self.free_defs(name).into_iter().filter(|d| self.files[d.0].krate == krate));
        dedup_refs(&out)
    }

    fn module_candidates(&self, fi: usize, path: &str) -> Vec<String> {
        let parts: Vec<&str> = path.split("::").collect();
        match parts[0] {
            "crate" => {
                let mut m = self.files[fi].krate.clone();
                if parts.len() > 1 {
                    m.push_str("::");
                    m.push_str(&parts[1..].join("::"));
                }
                vec![m]
            }
            "self" => {
                let mut m = self.files[fi].module.clone();
                if parts.len() > 1 {
                    m.push_str("::");
                    m.push_str(&parts[1..].join("::"));
                }
                vec![m]
            }
            "super" => {
                let mut m = self.files[fi].module.clone();
                let mut rest = parts[1..].to_vec();
                while rest.first().copied() == Some("super") {
                    rest.remove(0);
                    if let Some(pos) = m.rfind("::") {
                        m.truncate(pos);
                    }
                }
                if !rest.is_empty() {
                    m.push_str("::");
                    m.push_str(&rest.join("::"));
                }
                vec![m]
            }
            _ => vec![format!("{}::{}", self.files[fi].module, path), path.to_string()],
        }
    }

    /// Resolve a written path such as `crate::boot::App` or
    /// `my_service::registry::config::seed_from_env` to a free-fn
    /// definition. `None` means the path leaves the analyzed source set.
    pub fn resolve_path(&self, fi: usize, path: &str) -> Option<DefRef> {
        let mut seen = BTreeSet::new();
        self.resolve_hop(fi, path, &mut seen)
    }

    /// One resolution hop. `seen` blocks re-export cycles: a `(file, path)`
    /// pair is tried at most once, so mutual re-exports end the search
    /// (unresolved) instead of recursing forever.
    fn resolve_hop(&self, fi: usize, path: &str, seen: &mut BTreeSet<(usize, String)>) -> Option<DefRef> {
        let mut parts: Vec<&str> = path.split("::").collect();
        if parts.len() < 2 {
            return None;
        }
        let leaf = parts.pop().unwrap_or("").to_string();
        let candidates = self.module_candidates(fi, &parts.join("::"));
        for module in candidates {
            let mfi = match self.module_files.get(&module) {
                Some(i) => *i,
                None => continue,
            };
            for (oi, o) in self.files[mfi].fns.iter().enumerate() {
                if o.name == leaf && !o.in_test_region && o.owner == FnOwner::Free {
                    return Some((mfi, oi));
                }
            }
            // Re-export hop: the module re-exports the item through a use.
            if let Some(next) = self.files[mfi].uses.get(&leaf).and_then(|v| v.first()) {
                let next = next.clone();
                if seen.insert((mfi, next.clone()))
                    && let Some(d) = self.resolve_hop(mfi, &next, seen)
                {
                    return Some(d);
                }
                // The use names a module: the leaf lives inside it.
                if next.rsplit("::").next() != Some(leaf.as_str()) {
                    let child = format!("{next}::{leaf}");
                    if seen.insert((mfi, child.clone()))
                        && let Some(d) = self.resolve_hop(mfi, &child, seen)
                    {
                        return Some(d);
                    }
                }
                return None;
            }
            return None;
        }
        None
    }

    /// The type name an `impl`-less struct lookup wants: all fields of all
    /// struct definitions with this name (already indexed).
    #[must_use]
    pub fn has_struct(&self, ty: &str) -> bool {
        self.struct_fields.contains_key(ty)
    }
}

fn parse_use_tree(
    inner: &str,
    prefix: &str,
    uses: &mut BTreeMap<String, Vec<String>>,
    globs: &mut Vec<String>,
) {
    let chars: Vec<char> = inner.chars().collect();
    let mut cur = String::new();
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            '{' => {
                let start = i + 1;
                let mut depth = 1usize;
                let mut j = start;
                while j < chars.len() && depth > 0 {
                    match chars[j] {
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        _ => {}
                    }
                    if depth > 0 {
                        j += 1;
                    }
                }
                let nested: String = chars[start..j.min(chars.len())].iter().collect();
                let child = format!("{prefix}{}", cur.trim());
                parse_use_tree(&nested, &child, uses, globs);
                cur.clear();
                i = j + 1;
                continue;
            }
            ',' => {
                emit_use_item(&cur, prefix, uses, globs);
                cur.clear();
            }
            _ => cur.push(chars[i]),
        }
        i += 1;
    }
    emit_use_item(&cur, prefix, uses, globs);
}

fn emit_use_item(
    item: &str,
    prefix: &str,
    uses: &mut BTreeMap<String, Vec<String>>,
    globs: &mut Vec<String>,
) {
    let item = item.trim();
    if item.is_empty() {
        return;
    }
    if item == "*" || item.ends_with("::*") {
        let base = if item == "*" {
            prefix.to_string()
        } else {
            format!("{prefix}{}", item.trim_end_matches("::*"))
        };
        globs.push(base.trim_end_matches("::").to_string());
        return;
    }
    if let Some((p, alias)) = item.split_once(" as ") {
        uses.entry(alias.trim().to_string())
            .or_default()
            .push(format!("{prefix}{}", p.trim()));
        return;
    }
    let full = format!("{prefix}{item}");
    let leaf = item.rsplit("::").next().unwrap_or("").to_string();
    uses.entry(leaf).or_default().push(full);
}

fn dedup_refs(v: &[DefRef]) -> Vec<DefRef> {
    let mut out: Vec<DefRef> = Vec::new();
    for d in v {
        if !out.contains(d) {
            out.push(*d);
        }
    }
    out.sort();
    out
}

/// `impl Board for SqliteBoard` head -> (Some("Board"), Some("SqliteBoard"));
/// `impl SqliteRegistry` -> (None, Some("SqliteRegistry")).
fn split_impl_head(head: &str) -> (Option<String>, Option<String>) {
    let head = head.trim();
    if head.is_empty() {
        return (None, None);
    }
    if let Some((lhs, rhs)) = split_top_for(head) {
        return (first_ident(&lhs), first_ident(&rhs));
    }
    (None, first_ident(head))
}

fn split_top_for(head: &str) -> Option<(String, String)> {
    let bytes = head.as_bytes();
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth -= 1,
            _ => {}
        }
        if depth == 0 && head[i..].starts_with("for ") {
            return Some((head[..i].to_string(), head[i + 4..].to_string()));
        }
        i += 1;
    }
    None
}

fn first_ident(s: &str) -> Option<String> {
    let mut s = s.trim_start();
    // Skip a leading balanced generic parameter list: `<'a> Registry`.
    if let Some(rest) = s.strip_prefix('<') {
        let bytes = rest.as_bytes();
        let mut depth = 1usize;
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'<' => depth += 1,
                b'>' => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        s = &rest[i..];
    }
    let start = s.find(|c: char| c.is_alphabetic() || c == '_')?;
    let rest = &s[start..];
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// End offset of the item a `#[cfg(test)]` attribute governs.
fn region_end(f: &FileIdx, after_attr: usize) -> Option<usize> {
    let mb = f.masked.as_bytes();
    let mut i = after_attr;
    loop {
        while i < mb.len() && (mb[i] as char).is_whitespace() {
            i += 1;
        }
        if i < mb.len() && mb[i] == b'#' {
            let open = find_byte(mb, i, b"[")?;
            let mut depth = 0usize;
            let mut j = open;
            while j < mb.len() {
                match mb[j] {
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        break;
    }
    let skip = |s: &[u8]| -> Option<usize> {
        ["pub(", "pub ", "unsafe ", "async ", "const ", "extern "]
            .iter()
            .find_map(|k| if s.starts_with(k.as_bytes()) { Some(k.len()) } else { None })
    };
    // Skip visibility and modifiers to the item keyword.
    let mut j = i;
    while let Some(n) = skip(&f.masked.as_bytes()[j..]) {
        j += n;
        if f.masked[j..].starts_with('(') {
            j = find_byte(mb, j, b")").map(|p| p + 1).unwrap_or(j);
        }
        while j < mb.len() && (mb[j] as char).is_whitespace() {
            j += 1;
        }
    }
    let rest = &f.masked[j..];
    if rest.starts_with("use ") {
        return find_byte(mb, j, b";").map(|s| s + 1);
    }
    let is_const = rest.starts_with("const ") || rest.starts_with("static ");
    if let Some(open) = find_byte(mb, j, b"{") {
        let semi = find_byte(mb, j, b";");
        if !is_const {
            return block_end(mb, open);
        }
        if let Some(s) = semi
            && s < open
        {
            return Some(s + 1);
        }
        return block_end(mb, open);
    }
    find_byte(mb, j, b";").map(|s| s + 1)
}

fn parse_fields(f: &FileIdx, open: usize, end: usize) -> Vec<Field> {
    let mut out = Vec::new();
    let body = &f.masked[open + 1..end - 1];
    let base = open + 1;
    let mut depth = 0i32;
    let mut seg_start = 0usize;
    let mut segments: Vec<(usize, &str)> = Vec::new();
    for (k, c) in body.bytes().enumerate() {
        match c {
            b'<' | b'(' | b'[' | b'{' => depth += 1,
            b'>' | b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                segments.push((seg_start, &body[seg_start..k]));
                seg_start = k + 1;
            }
            _ => {}
        }
    }
    segments.push((seg_start, &body[seg_start..]));
    for (soff, seg) in segments {
        if let Some(cap) = RE_FIELD.captures(seg) {
            let name = cap.get(1).unwrap().as_str().to_string();
            let ty = cap.get(2).unwrap().as_str().trim().to_string();
            let inner = seg.find(':').unwrap_or(0) + 2;
            out.push(Field {
                name,
                ty,
                offset: base + soff + inner,
            });
        }
    }
    out
}

fn parse_file(krate: String, module: String, path: String, text: String) -> FileIdx {
    let (masked, strings) = mask(&text);
    let newlines = byte_indices_of(&text, b'\n');
    let mut f = FileIdx {
        krate,
        module,
        path,
        text,
        masked,
        strings,
        newlines,
        fns: Vec::new(),
        uses: BTreeMap::new(),
        globs: Vec::new(),
        test_regions: Vec::new(),
    };
    f.test_regions = RE_CFG_TEST
        .find_iter(&f.masked)
        .filter_map(|m| region_end(&f, m.end()).map(|e| (m.start(), e)))
        .collect();
    let mut uses: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut globs: Vec<String> = Vec::new();
    for cap in RE_USE_PLAIN.captures_iter(&f.masked) {
        let full = cap.get(1).unwrap().as_str().to_string();
        let leaf = cap
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| full.rsplit("::").next().unwrap_or("").to_string());
        uses.entry(leaf).or_default().push(full);
    }
    for cap in RE_USE_TREE.captures_iter(&f.masked) {
        let prefix = format!(
            "{}::",
            cap.get(1)
                .unwrap()
                .as_str()
                .trim_start_matches(':')
                .trim_end_matches(':')
        );
        let inner = cap.get(2).unwrap().as_str();
        parse_use_tree(inner, &prefix, &mut uses, &mut globs);
    }
    f.uses = uses;
    f.globs = globs;
    f
}

/// Find the body of an fn: `after_open` is one past the opening paren of
/// the parameter list (the RE_FN capture ends there). Returns the `{` pair
/// of the body, or a `;` marker (trait signature without a body).
fn fn_body_open(mb: &[u8], after_open: usize) -> Option<(usize, bool)> {
    let mut depth = 1usize;
    let mut i = after_open;
    while i < mb.len() {
        match mb[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let mut j = i + 1;
    let mut depth = 0i32;
    while j < mb.len() {
        match mb[j] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' if depth > 0 => depth -= 1,
            b'{' if depth == 0 => return Some((j, false)),
            b';' if depth == 0 => return Some((j, true)),
            _ => {}
        }
        j += 1;
    }
    None
}

fn byte_indices_of(text: &str, needle: u8) -> Vec<usize> {
    text.bytes()
        .enumerate()
        .filter(|(_, b)| *b == needle)
        .map(|(i, _)| i)
        .collect()
}

/// `crates/x/src/http/api/mod.rs` -> `x::http::api`.
fn module_path(krate: &str, rel: &str) -> String {
    let without_ext = rel.rsplit_once('.').map(|(a, _)| a).unwrap_or(rel);
    let mut parts: Vec<&str> = without_ext.split('/').collect();
    if let Some(pos) = parts.iter().rposition(|p| *p == "src") {
        parts = parts[pos + 1..].to_vec();
    }
    if parts.last().copied() == Some("mod") {
        parts.pop();
    } else if parts.last().copied().is_some_and(|last| (last == "lib" || last == "main") && parts.len() == 1) {
        return krate.to_string();
    }
    let mut out = vec![krate.to_string()];
    out.extend(parts.iter().map(|p| p.to_string()));
    out.join("::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_blanks_strings_and_comments_keeps_lines() {
        let src = "let a = \"INSERT INTO x\"; // FROM y\nlet b = 2;\n";
        let (m, strings) = mask(src);
        assert_eq!(m.lines().count(), src.lines().count());
        assert!(!m.contains("INSERT"));
        assert!(!m.contains("FROM y"));
        assert!(m.contains("let a ="), "code bytes must survive masking");
        assert!(m.contains("let b = 2"));
        assert_eq!(strings.len(), 1);
        assert_eq!(&src[strings[0].0..strings[0].1], "INSERT INTO x");
    }

    #[test]
    fn mask_raw_string() {
        let src = "const S: &str = r#\"INSERT INTO t\"#;\nlet x = 1;\n";
        let (m, strings) = mask(src);
        assert!(!m.contains("INSERT"));
        assert_eq!(strings.len(), 1);
        assert_eq!(&src[strings[0].0..strings[0].1], "INSERT INTO t");
    }

    #[test]
    fn module_paths() {
        assert_eq!(module_path("x", "crates/x/src/main.rs"), "x");
        assert_eq!(module_path("x", "crates/x/src/http/mod.rs"), "x::http");
        assert_eq!(module_path("x", "crates/x/src/http/api.rs"), "x::http::api");
    }

    #[test]
    fn impl_head_split() {
        assert_eq!(
            split_impl_head("Board for SqliteBoard"),
            (Some("Board".into()), Some("SqliteBoard".into()))
        );
        assert_eq!(split_impl_head("SqliteRegistry"), (None, Some("SqliteRegistry".into())));
        assert_eq!(
            split_impl_head("<'a> Registry for SqliteRegistry"),
            (Some("Registry".into()), Some("SqliteRegistry".into()))
        );
    }
}
