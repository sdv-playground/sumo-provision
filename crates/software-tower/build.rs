// Recompile whenever a migration is added or changed, so the embedded set from
// `sqlx::migrate!("./migrations")` (a compile-time macro) is refreshed.
//
// Without this, cargo does NOT re-run the macro when only a new `.sql` file
// appears — the source `.rs` is unchanged, so the incremental build reuses the
// stale binary and the new migration silently never embeds (it never runs, and
// its schema change never applies). That bit us with migration 0004.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
