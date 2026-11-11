//! Golden-diff helper: print `build_report` as JSON for a DB, with no live service lookups.
//! usage: dump_report <memwatch.db> <now>
use std::collections::HashSet;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let conn = memwatch::db::connect(std::path::Path::new(&a[1])).unwrap();
    let cfg = memwatch::config::load_config(Some(std::path::Path::new("nonexistent.toml")));
    let now: i64 = a[2].parse().unwrap();
    let r = memwatch::suggest::build_report(&conn, &cfg, now, &HashSet::new(), &|_| vec![], &|_| String::new()).unwrap();
    println!("{}", serde_json::to_string(&r).unwrap());
}
