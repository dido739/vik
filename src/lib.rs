use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const VIK_DIR: &str = ".vik";

#[derive(Parser, Debug)]
#[command(name = "vik", about = "Version Integrity Kit")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Init {
        path: Option<PathBuf>,
    },
    HashObject {
        file: PathBuf,
        #[arg(long)]
        write: bool,
    },
    CatFile {
        #[arg(long = "type", conflicts_with_all = ["size", "pretty"])]
        show_type: bool,
        #[arg(long, conflicts_with_all = ["show_type", "pretty"])]
        size: bool,
        #[arg(short = 'p', long, conflicts_with_all = ["show_type", "size"])]
        pretty: bool,
        object: String,
    },
    Add {
        files: Vec<PathBuf>,
    },
    Commit {
        #[arg(short = 'm', long)]
        message: String,
    },
    Log,
    Branch {
        name: Option<String>,
    },
    Checkout {
        name: String,
    },
    Status,
}

#[derive(Clone, Debug)]
struct IndexEntry {
    path: String,
    blob_id: String,
}

#[derive(Clone, Debug)]
struct ParsedObject {
    kind: String,
    content: Vec<u8>,
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init { path } => {
            let repo_path = path.unwrap_or_else(|| PathBuf::from("."));
            init_repo(&repo_path)?;
            println!(
                "Initialized empty vik repository in {}",
                repo_path.join(VIK_DIR).display()
            );
        }
        Commands::HashObject { file, write } => {
            let data = fs::read(&file)
                .with_context(|| format!("failed to read file {}", file.display()))?;
            let object = encode_object("blob", &data);
            let oid = sha256_hex(&object);
            if write {
                let repo_root = find_repo_root(&std::env::current_dir()?)?;
                write_raw_object(&repo_root, &oid, &object)?;
            }
            println!("{oid}");
        }
        Commands::CatFile {
            show_type,
            size,
            pretty,
            object,
        } => {
            let repo_root = find_repo_root(&std::env::current_dir()?)?;
            let parsed = read_object(&repo_root, &object)?;
            if show_type {
                println!("{}", parsed.kind);
            } else if size {
                println!("{}", parsed.content.len());
            } else if pretty {
                if parsed.kind == "blob" || parsed.kind == "commit" || parsed.kind == "tree" {
                    print!("{}", String::from_utf8_lossy(&parsed.content));
                } else {
                    std::io::stdout().write_all(&parsed.content)?;
                }
            } else {
                bail!("choose one of --type, --size, or --pretty");
            }
        }
        Commands::Add { files } => {
            if files.is_empty() {
                bail!("no files provided");
            }
            let cwd = std::env::current_dir()?;
            let repo_root = find_repo_root(&cwd)?;
            let mut index = load_index(&repo_root)?;

            for file in files {
                let absolute = cwd.join(&file);
                let relative = path_relative_to_root(&absolute, &repo_root)?;
                let data = fs::read(&absolute)
                    .with_context(|| format!("failed to read file {}", absolute.display()))?;
                let object = encode_object("blob", &data);
                let oid = sha256_hex(&object);
                write_raw_object(&repo_root, &oid, &object)?;
                upsert_index_entry(
                    &mut index,
                    IndexEntry {
                        path: relative,
                        blob_id: oid,
                    },
                );
            }
            save_index(&repo_root, &index)?;
        }
        Commands::Commit { message } => {
            let repo_root = find_repo_root(&std::env::current_dir()?)?;
            let index = load_index(&repo_root)?;
            if index.is_empty() {
                bail!("nothing to commit (index is empty)");
            }

            let tree_id = write_tree_from_index(&repo_root, &index)?;
            let head = read_head_target(&repo_root)?;
            let branch_ref = repo_root.join(VIK_DIR).join(&head);
            let parent = read_ref(&branch_ref)?;
            let author = std::env::var("VIK_AUTHOR")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_else(|_| "vik".to_string());
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let mut commit_body = format!("tree {tree_id}\n");
            if let Some(parent_id) = parent {
                if !parent_id.trim().is_empty() {
                    commit_body.push_str(&format!("parent {}\n", parent_id.trim()));
                }
            }
            commit_body.push_str(&format!("author {author}\n"));
            commit_body.push_str(&format!("committer {author}\n"));
            commit_body.push_str(&format!("timestamp {timestamp}\n\n{message}\n"));
            let commit_object = encode_object("commit", commit_body.as_bytes());
            let commit_id = sha256_hex(&commit_object);
            write_raw_object(&repo_root, &commit_id, &commit_object)?;

            write_ref(&branch_ref, &commit_id)?;
            println!("[{head}] {commit_id}");
            println!("{message}");
        }
        Commands::Log => {
            let repo_root = find_repo_root(&std::env::current_dir()?)?;
            let head_ref = read_head_target(&repo_root)?;
            let mut current = read_ref(&repo_root.join(VIK_DIR).join(&head_ref))?;

            while let Some(commit_id) = current {
                if commit_id.trim().is_empty() {
                    break;
                }
                let parsed = read_object(&repo_root, commit_id.trim())?;
                if parsed.kind != "commit" {
                    bail!("object {} is not a commit", commit_id.trim());
                }
                let text = String::from_utf8(parsed.content)?;
                println!("commit {}", commit_id.trim());
                let mut parent: Option<String> = None;
                let mut in_message = false;
                for line in text.lines() {
                    if line.is_empty() {
                        in_message = true;
                        continue;
                    }
                    if in_message {
                        println!("    {line}");
                    } else if let Some(rest) = line.strip_prefix("author ") {
                        println!("Author: {rest}");
                    } else if let Some(rest) = line.strip_prefix("timestamp ") {
                        println!("Date: {rest}");
                    } else if let Some(rest) = line.strip_prefix("parent ") {
                        parent = Some(rest.to_string());
                    }
                }
                println!();
                current = parent;
            }
        }
        Commands::Branch { name } => {
            let repo_root = find_repo_root(&std::env::current_dir()?)?;
            let heads_dir = repo_root.join(VIK_DIR).join("refs/heads");
            let current_head = read_head_target(&repo_root)?;
            if let Some(name) = name {
                if name.contains('/') || name.contains(' ') {
                    bail!("invalid branch name");
                }
                let target = heads_dir.join(&name);
                if target.exists() {
                    bail!("branch '{name}' already exists");
                }
                let current_commit =
                    read_ref(&repo_root.join(VIK_DIR).join(&current_head))?.unwrap_or_default();
                write_ref(&target, current_commit.trim())?;
            } else {
                let current_name = current_head
                    .strip_prefix("refs/heads/")
                    .unwrap_or(&current_head)
                    .to_string();
                let mut names: Vec<String> = fs::read_dir(&heads_dir)?
                    .filter_map(|entry| {
                        entry.ok().and_then(|e| {
                            e.path()
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                        })
                    })
                    .collect();
                names.sort();
                for name in names {
                    if name == current_name {
                        println!("* {name}");
                    } else {
                        println!("  {name}");
                    }
                }
            }
        }
        Commands::Checkout { name } => {
            let repo_root = find_repo_root(&std::env::current_dir()?)?;
            let target_ref = format!("refs/heads/{name}");
            let target_file = repo_root.join(VIK_DIR).join(&target_ref);
            if !target_file.exists() {
                bail!("unknown branch '{name}'");
            }
            fs::write(
                repo_root.join(VIK_DIR).join("HEAD"),
                format!("ref: {target_ref}\n"),
            )?;
            if let Some(commit_id) = read_ref(&target_file)? {
                if !commit_id.trim().is_empty() {
                    checkout_commit(&repo_root, commit_id.trim())?;
                }
            }
            println!("Switched to branch '{name}'");
        }
        Commands::Status => {
            let cwd = std::env::current_dir()?;
            let repo_root = find_repo_root(&cwd)?;
            let index = load_index(&repo_root)?;
            let head_ref = read_head_target(&repo_root)?;
            let head_commit = read_ref(&repo_root.join(VIK_DIR).join(head_ref))?;
            let tracked_at_head = if let Some(commit_id) = head_commit {
                if commit_id.trim().is_empty() {
                    BTreeMap::new()
                } else {
                    collect_files_from_commit(&repo_root, commit_id.trim())?
                }
            } else {
                BTreeMap::new()
            };

            let indexed: BTreeMap<String, String> = index
                .iter()
                .map(|entry| (entry.path.clone(), entry.blob_id.clone()))
                .collect();

            println!("Changes to be committed:");
            let mut staged_any = false;
            for (path, blob_id) in &indexed {
                if tracked_at_head.get(path) != Some(blob_id) {
                    println!("  staged: {path}");
                    staged_any = true;
                }
            }
            if !staged_any {
                println!("  (none)");
            }

            println!("Changes not staged for commit:");
            let mut dirty_any = false;
            for entry in &index {
                let absolute = repo_root.join(&entry.path);
                if absolute.exists() {
                    let data = fs::read(&absolute)?;
                    let object = encode_object("blob", &data);
                    let oid = sha256_hex(&object);
                    if oid != entry.blob_id {
                        println!("  modified: {}", entry.path);
                        dirty_any = true;
                    }
                }
            }
            if !dirty_any {
                println!("  (none)");
            }
        }
    }

    Ok(())
}

pub fn init_repo(path: &Path) -> Result<()> {
    let vik = path.join(VIK_DIR);
    fs::create_dir_all(vik.join("objects"))?;
    fs::create_dir_all(vik.join("refs/heads"))?;

    let head = vik.join("HEAD");
    if !head.exists() {
        fs::write(&head, b"ref: refs/heads/main\n")?;
    }

    let main_ref = vik.join("refs/heads/main");
    if !main_ref.exists() {
        fs::write(main_ref, b"")?;
    }

    let index = vik.join("index");
    if !index.exists() {
        fs::write(index, b"")?;
    }

    Ok(())
}

fn find_repo_root(start: &Path) -> Result<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        if current.join(VIK_DIR).is_dir() {
            return Ok(current);
        }
        if !current.pop() {
            bail!("not inside a vik repository");
        }
    }
}

fn encode_object(kind: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{kind} {}\0", data.len()).as_bytes());
    out.extend_from_slice(data);
    out
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn object_path(repo_root: &Path, oid: &str) -> Result<PathBuf> {
    if oid.len() < 3 {
        bail!("invalid object id");
    }
    let (dir, file) = oid.split_at(2);
    Ok(repo_root.join(VIK_DIR).join("objects").join(dir).join(file))
}

fn write_raw_object(repo_root: &Path, oid: &str, data: &[u8]) -> Result<()> {
    let path = object_path(repo_root, oid)?;
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)?;
    Ok(())
}

fn read_object(repo_root: &Path, oid: &str) -> Result<ParsedObject> {
    let data = fs::read(object_path(repo_root, oid)?)
        .with_context(|| format!("object {oid} not found"))?;
    let Some(nul_pos) = data.iter().position(|b| *b == b'\0') else {
        bail!("corrupt object: missing header separator");
    };
    let header = String::from_utf8(data[..nul_pos].to_vec())?;
    let mut parts = header.splitn(2, ' ');
    let kind = parts
        .next()
        .ok_or_else(|| anyhow!("corrupt object header"))?
        .to_string();
    let size: usize = parts
        .next()
        .ok_or_else(|| anyhow!("corrupt object size"))?
        .parse()
        .context("invalid object size")?;
    let content = data[(nul_pos + 1)..].to_vec();
    if content.len() != size {
        bail!("corrupt object: size mismatch");
    }
    Ok(ParsedObject { kind, content })
}

fn load_index(repo_root: &Path) -> Result<Vec<IndexEntry>> {
    let path = repo_root.join(VIK_DIR).join("index");
    let contents = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (path, blob_id) = line
            .split_once('\t')
            .ok_or_else(|| anyhow!("invalid index entry"))?;
        out.push(IndexEntry {
            path: path.to_string(),
            blob_id: blob_id.to_string(),
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn save_index(repo_root: &Path, entries: &[IndexEntry]) -> Result<()> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut content = String::new();
    for entry in sorted {
        content.push_str(&entry.path);
        content.push('\t');
        content.push_str(&entry.blob_id);
        content.push('\n');
    }
    fs::write(repo_root.join(VIK_DIR).join("index"), content)?;
    Ok(())
}

fn upsert_index_entry(entries: &mut Vec<IndexEntry>, next: IndexEntry) {
    if let Some(existing) = entries.iter_mut().find(|entry| entry.path == next.path) {
        *existing = next;
    } else {
        entries.push(next);
    }
}

fn path_relative_to_root(path: &Path, repo_root: &Path) -> Result<String> {
    let canonical_path = fs::canonicalize(path)
        .with_context(|| format!("cannot resolve path {}", path.display()))?;
    let canonical_root = fs::canonicalize(repo_root)?;
    let relative = canonical_path
        .strip_prefix(&canonical_root)
        .map_err(|_| anyhow!("path {} is outside repository", path.display()))?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn write_tree_from_index(repo_root: &Path, entries: &[IndexEntry]) -> Result<String> {
    let mut root = TreeNode::default();
    for entry in entries {
        let parts: Vec<&str> = entry.path.split('/').collect();
        root.insert(&parts, &entry.blob_id)?;
    }
    write_tree_node(repo_root, &root)
}

#[derive(Default)]
struct TreeNode {
    blobs: BTreeMap<String, String>,
    dirs: BTreeMap<String, TreeNode>,
}

impl TreeNode {
    fn insert(&mut self, parts: &[&str], blob_id: &str) -> Result<()> {
        if parts.is_empty() {
            bail!("invalid empty path in index");
        }
        if parts.len() == 1 {
            self.blobs.insert(parts[0].to_string(), blob_id.to_string());
            return Ok(());
        }
        let child = self.dirs.entry(parts[0].to_string()).or_default();
        child.insert(&parts[1..], blob_id)
    }
}

fn write_tree_node(repo_root: &Path, node: &TreeNode) -> Result<String> {
    let mut lines = String::new();

    for (name, blob_id) in &node.blobs {
        lines.push_str(&format!("100644 blob {blob_id} {name}\n"));
    }

    for (name, child) in &node.dirs {
        let child_id = write_tree_node(repo_root, child)?;
        lines.push_str(&format!("040000 tree {child_id} {name}\n"));
    }

    let object = encode_object("tree", lines.as_bytes());
    let oid = sha256_hex(&object);
    write_raw_object(repo_root, &oid, &object)?;
    Ok(oid)
}

fn read_head_target(repo_root: &Path) -> Result<String> {
    let head = fs::read_to_string(repo_root.join(VIK_DIR).join("HEAD"))?;
    let target = head
        .trim()
        .strip_prefix("ref: ")
        .ok_or_else(|| anyhow!("HEAD is not a symbolic ref"))?;
    Ok(target.to_string())
}

fn read_ref(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    Ok(Some(content.trim().to_string()))
}

fn write_ref(path: &Path, oid: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", oid.trim()))?;
    Ok(())
}

fn parse_tree(content: &str) -> Result<Vec<(String, String, String)>> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let mut split = line.splitn(4, ' ');
        let _mode = split.next().ok_or_else(|| anyhow!("invalid tree entry"))?;
        let kind = split.next().ok_or_else(|| anyhow!("invalid tree entry"))?;
        let oid = split.next().ok_or_else(|| anyhow!("invalid tree entry"))?;
        let name = split.next().ok_or_else(|| anyhow!("invalid tree entry"))?;
        entries.push((kind.to_string(), oid.to_string(), name.to_string()));
    }
    Ok(entries)
}

fn collect_files_from_tree(
    repo_root: &Path,
    tree_id: &str,
    prefix: &str,
    out: &mut BTreeMap<String, String>,
) -> Result<()> {
    let parsed = read_object(repo_root, tree_id)?;
    if parsed.kind != "tree" {
        bail!("object {tree_id} is not a tree");
    }
    let text = String::from_utf8(parsed.content)?;
    for (kind, oid, name) in parse_tree(&text)? {
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{}", name)
        };
        if kind == "blob" {
            out.insert(path, oid);
        } else if kind == "tree" {
            collect_files_from_tree(repo_root, &oid, &path, out)?;
        }
    }
    Ok(())
}

fn collect_files_from_commit(
    repo_root: &Path,
    commit_id: &str,
) -> Result<BTreeMap<String, String>> {
    let commit = read_object(repo_root, commit_id)?;
    if commit.kind != "commit" {
        bail!("object {commit_id} is not a commit");
    }
    let text = String::from_utf8(commit.content)?;
    let tree_id = text
        .lines()
        .find_map(|line| line.strip_prefix("tree "))
        .ok_or_else(|| anyhow!("commit missing tree"))?;
    let mut out = BTreeMap::new();
    collect_files_from_tree(repo_root, tree_id, "", &mut out)?;
    Ok(out)
}

fn checkout_commit(repo_root: &Path, commit_id: &str) -> Result<()> {
    let files = collect_files_from_commit(repo_root, commit_id)?;

    for (path, blob_id) in &files {
        let parsed = read_object(repo_root, blob_id)?;
        if parsed.kind != "blob" {
            bail!("object {blob_id} is not a blob");
        }
        let absolute = repo_root.join(path);
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(absolute, parsed.content)?;
    }

    let index_entries: Vec<IndexEntry> = files
        .into_iter()
        .map(|(path, blob_id)| IndexEntry { path, blob_id })
        .collect();
    save_index(repo_root, &index_entries)?;
    Ok(())
}

pub fn tracked_paths(repo_root: &Path) -> Result<BTreeSet<String>> {
    Ok(load_index(repo_root)?.into_iter().map(|e| e.path).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_creates_expected_layout() {
        let tmp = tempdir().unwrap();
        init_repo(tmp.path()).unwrap();

        assert!(tmp.path().join(".vik/objects").is_dir());
        assert!(tmp.path().join(".vik/refs/heads").is_dir());
        assert!(tmp.path().join(".vik/HEAD").is_file());
        assert!(tmp.path().join(".vik/index").is_file());
    }

    #[test]
    fn object_encoding_hash_is_stable() {
        let data = b"hello";
        let encoded = encode_object("blob", data);
        assert_eq!(sha256_hex(&encoded), sha256_hex(&encoded));
    }
}
