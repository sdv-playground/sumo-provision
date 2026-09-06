//! **The canonical param-blob, and the hash is over exactly these bytes.**
//!
//! An assignment is stored as columns and served as a DOCUMENT, and the document
//! is what a delivery path content-addresses: Tower 2 keeps a configuration as a
//! [`wire::Part`] `{ kind: "param-blob", id: <set_id>, content: <this hash> }`,
//! which is a reference by hash and by nothing else. So the bytes have to be a
//! function of the assignment and of nothing about the machine that rendered
//! them.
//!
//! ```text
//! {"set":"vehicle-attributes","model":"managed-cvc","version":"0df1d79","revision":1,
//!  "values":{"Vehicle.Chassis.AxleCount":2,"Vehicle.Chassis.WheelbaseMm":2900.0}}
//! ```
//!
//! (on one line — the wrap above is this comment's). What makes that canonical:
//!
//! - the five fields in THIS order, which is the order they are declared in
//!   [`Blob`] and the order `serde_json` writes a struct in;
//! - `values` in KEY ORDER, which is [`Values`] being a `BTreeMap` and not a
//!   convention anybody has to hold to;
//! - NO WHITESPACE — `serde_json::to_vec`, never `to_vec_pretty`;
//! - the numbers as `serde_json` writes them, which is how they arrived: a value
//!   is carried from the request to the blob without a round trip through any
//!   other numeric type.
//!
//! `GET …/blob` serves [`render`]'s output and `content_hash` is
//! [`ContentHash::of`] over it, in the repo-wide `sha256:<hex>` form — so a
//! client that fetches the blob and hashes it gets the hash the tower reported,
//! and Tower 2 can reference the same bytes without re-deriving anything.

use std::collections::BTreeMap;

use serde::Serialize;
use wire::ContentHash;

/// One set's values: JSON as sent, in key order.
pub type Values = BTreeMap<String, serde_json::Value>;

/// The document one assignment IS.
#[derive(Serialize)]
pub struct Blob<'a> {
    pub set: &'a str,
    pub model: &'a str,
    pub version: &'a str,
    pub revision: i64,
    pub values: &'a Values,
}

/// The canonical bytes. Compact, in declaration order, keys sorted.
pub fn render(blob: &Blob<'_>) -> Vec<u8> {
    // A `Blob` is three strings, a number and a map of JSON values: there is no
    // shape in it that `serde_json` can refuse to write, so the serialisation
    // cannot fail and an error path here would be one nothing could reach.
    serde_json::to_vec(blob).expect("a blob of JSON values is JSON")
}

/// The blob's content address, as `sha256:<hex>`.
pub fn hash(bytes: &[u8]) -> String {
    ContentHash::of(bytes).to_prefixed()
}
