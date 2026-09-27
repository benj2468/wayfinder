//! The certificate authority's durable store: record-level rows in SQLite
//! (design 26 phase 2).
//!
//! The CA's state used to be one JSON document rewritten whole on every
//! mutation — logins included — and read back through a 1 MiB cap that turned
//! the log's growth into a CA that refused to start. Here each record is its
//! own row, a mutation writes only the rows it changed, and a mutation that
//! spans two collections commits as one transaction.
//!
//! # Rows are keyed by content, not by a domain key
//!
//! None of the collections has a natural unique key — the issued log holds
//! every certificate a MAC was ever given, and a MAC can have several held
//! CSRs — and the authority mutates them as whole `Vec`s through
//! [`CaLog`](crate::persistence::CaLog)'s sealed `mutate_*` closures. So a row
//! is `(id, body)`: the record's serialised form under a store-assigned id, and
//! a mutation becomes the multiset difference between the bodies before and
//! after it — delete the rows whose bodies disappeared, insert the new ones.
//! An unchanged record is never rewritten.
//!
//! # Why a trait
//!
//! [`CaStore`] is the seam a second backend (PostgreSQL, when a second CA
//! instance or an outside reader needs one — design 26 §8) plugs into. Nothing
//! above it names SQLite.

/// A collection of CA records, each a table of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Collection {
    /// The issued-certificate log.
    Issued,
    /// Held certificate signing requests.
    Held,
    /// The operator's enrollment-policy overrides: at most one row.
    Policy,
    /// User accounts.
    Users,
    /// Pending account invitations.
    Invites,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SqliteStore {
        SqliteStore::open_in_memory().unwrap()
    }

    fn body(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    /// A store nothing has ever been committed to is distinguishable from one
    /// that holds an empty CA: the first is where a `ca-state.json` import
    /// happens, the second must never trigger one.
    #[test]
    fn a_fresh_store_is_uninitialized() {
        let mut s = store();
        let loaded = s.load().unwrap();
        assert!(!loaded.initialized);
        assert!(loaded.rows.is_empty());

        s.commit(&ChangeSet::default()).unwrap();
        let loaded = s.load().unwrap();
        assert!(
            loaded.initialized,
            "any commit, even an empty one, initializes"
        );
        assert!(loaded.rows.is_empty());
    }

    /// Inserted rows come back from `load` under the ids `commit` assigned,
    /// in their own collections.
    #[test]
    fn committed_rows_load_back_in_their_collections() {
        let mut s = store();
        let mut change = ChangeSet::default();
        change.insert(Collection::Issued, body("a"));
        change.insert(Collection::Held, body("b"));
        change.insert(Collection::Issued, body("c"));
        let ids = s.commit(&change).unwrap();
        assert_eq!(ids.len(), 3);

        let loaded = s.load().unwrap();
        let mut rows = loaded.rows.clone();
        rows.sort_by_key(|r| r.id);
        assert_eq!(
            rows,
            vec![
                Row {
                    collection: Collection::Issued,
                    id: ids[0],
                    body: body("a")
                },
                Row {
                    collection: Collection::Held,
                    id: ids[1],
                    body: body("b")
                },
                Row {
                    collection: Collection::Issued,
                    id: ids[2],
                    body: body("c")
                },
            ]
        );
    }

    /// A delete removes exactly the row it names, leaving an identical body in
    /// another row alone — the multiset case two equal records produce.
    #[test]
    fn a_delete_removes_one_row_even_among_identical_bodies() {
        let mut s = store();
        let mut change = ChangeSet::default();
        change.insert(Collection::Users, body("same"));
        change.insert(Collection::Users, body("same"));
        let ids = s.commit(&change).unwrap();

        let mut change = ChangeSet::default();
        change.delete(Collection::Users, ids[0]);
        s.commit(&change).unwrap();

        let loaded = s.load().unwrap();
        assert_eq!(loaded.rows.len(), 1);
        assert_eq!(loaded.rows[0].id, ids[1]);
    }

    /// A change set commits whole or not at all. A delete naming a row that
    /// does not exist means the caller's view of the store has diverged from
    /// the store, and the inserts beside it must not land either.
    #[test]
    fn a_failing_change_set_leaves_nothing_behind() {
        let mut s = store();
        let mut change = ChangeSet::default();
        change.insert(Collection::Issued, body("kept"));
        s.commit(&change).unwrap();

        let mut change = ChangeSet::default();
        change.insert(Collection::Issued, body("must not land"));
        change.insert(Collection::Invites, body("nor this"));
        change.delete(Collection::Held, 9_999);
        assert!(s.commit(&change).is_err());

        let loaded = s.load().unwrap();
        assert_eq!(
            loaded.rows.len(),
            1,
            "the failed change set left rows behind"
        );
        assert_eq!(loaded.rows[0].body, body("kept"));
    }

    /// A delete must name the row in the collection it says: an id from one
    /// table is not a licence to delete from another.
    #[test]
    fn a_delete_in_the_wrong_collection_fails() {
        let mut s = store();
        let mut change = ChangeSet::default();
        change.insert(Collection::Issued, body("x"));
        let ids = s.commit(&change).unwrap();

        let mut change = ChangeSet::default();
        change.delete(Collection::Held, ids[0]);
        assert!(s.commit(&change).is_err());
        assert_eq!(s.load().unwrap().rows.len(), 1);
    }

    /// The table layout is versioned, and a database written by a newer build
    /// fails closed rather than being read under a layout it was not written in.
    #[test]
    fn a_database_from_a_newer_schema_fails_closed() {
        let dir = tempdir("newer-schema");
        let path = dir.join("ca.sqlite3");
        SqliteStore::open(&path).unwrap();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        let err = SqliteStore::open(&path)
            .err()
            .expect("a newer schema must not open");
        assert!(err.contains("newer"), "unhelpful error: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Rows survive closing and reopening the file, which is the whole point.
    #[test]
    fn rows_survive_reopening_the_database() {
        let dir = tempdir("reopen");
        let path = dir.join("ca.sqlite3");
        {
            let mut s = SqliteStore::open(&path).unwrap();
            let mut change = ChangeSet::default();
            change.insert(Collection::Policy, body("p"));
            s.commit(&change).unwrap();
        }
        let loaded = SqliteStore::open(&path).unwrap().load().unwrap();
        assert!(loaded.initialized);
        assert_eq!(loaded.rows.len(), 1);
        assert_eq!(loaded.rows[0].body, body("p"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The database holds the enrollment token and password hashes, so it is
    /// created owner-only, as the JSON snapshot was.
    #[test]
    fn the_database_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir("mode");
        let path = dir.join("ca.sqlite3");
        SqliteStore::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "database mode is {mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn tempdir(label: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "wayfinder-ca-store-test-{}-{label}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
