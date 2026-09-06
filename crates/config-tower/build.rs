// Recompile whenever a migration is added or changed, so the embedded set from
// `sqlx::migrate!("./migrations")` (a compile-time macro) is refreshed. Same
// reason as Tower 2's build.rs: cargo does NOT re-run the macro when only a new
// `.sql` file appears, so the new migration would silently never embed.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
