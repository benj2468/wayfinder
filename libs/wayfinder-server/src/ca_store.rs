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

/// A collection of CA records. Stored in one table, tagged by collection.
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

impl Collection {
    /// Every collection, in the order a snapshot lists them.
    pub(crate) const ALL: [Collection; 5] = [
        Collection::Issued,
        Collection::Held,
        Collection::Policy,
        Collection::Users,
        Collection::Invites,
    ];

    /// The name this collection is stored under. Part of the on-disk format:
    /// changing one orphans every row already written under it.
    fn as_str(self) -> &'static str {
        match self {
            Collection::Issued => "issued",
            Collection::Held => "held",
            Collection::Policy => "policy",
            Collection::Users => "users",
            Collection::Invites => "invites",
        }
    }

    /// The collection stored under `name`, if it is one this build knows.
    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// One stored record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    /// The collection the record belongs to.
    pub(crate) collection: Collection,
    /// The store-assigned id. Never reused, so an id the caller remembers can
    /// never come to name a different record.
    pub(crate) id: i64,
    /// The record's serialised form. Opaque to the store.
    pub(crate) body: Vec<u8>,
}

/// Everything a store holds.
#[derive(Clone, Debug, Default)]
pub(crate) struct Loaded {
    /// Whether anything has ever been committed. `false` is a store that has
    /// never held a CA; an empty CA that has committed is `true`.
    pub(crate) initialized: bool,
    /// Every row, in no particular order.
    pub(crate) rows: Vec<Row>,
}

/// One atomic change: rows to insert and rows to delete, applied together or
/// not at all.
#[derive(Clone, Debug, Default)]
pub(crate) struct ChangeSet {
    inserts: Vec<(Collection, Vec<u8>)>,
    deletes: Vec<(Collection, i64)>,
}

impl ChangeSet {
    /// Insert a new row holding `body` into `collection`.
    pub(crate) fn insert(&mut self, collection: Collection, body: Vec<u8>) {
        self.inserts.push((collection, body));
    }

    /// Delete row `id`, which must exist in `collection`.
    pub(crate) fn delete(&mut self, collection: Collection, id: i64) {
        self.deletes.push((collection, id));
    }

    /// The rows this change inserts, in the order [`CaStore::commit`] assigns
    /// their ids.
    pub(crate) fn inserts(&self) -> &[(Collection, Vec<u8>)] {
        &self.inserts
    }

    /// Whether this change writes nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.inserts.is_empty() && self.deletes.is_empty()
    }
}

/// Where the certificate authority's records live.
pub(crate) trait CaStore: Send {
    /// Read every row, and whether the store has ever been committed to.
    fn load(&mut self) -> Result<Loaded, String>;

    /// Apply `change` as one transaction, returning the ids assigned to its
    /// inserts in order. Marks the store initialized, even for an empty change.
    ///
    /// All or nothing: a delete naming a row that is not in its collection
    /// means the caller's view has diverged from the store, and fails the
    /// whole change rather than applying the parts that still make sense.
    fn commit(&mut self, change: &ChangeSet) -> Result<Vec<i64>, String>;
}

/// The table layout this build reads and writes, in SQLite's `user_version`.
///
/// It versions the *tables*, not the records: a record body carries its own
/// serde shape, and gains a field the way the JSON snapshot always did, with a
/// default. Bump this, and add a step to [`migrate`], only when the tables
/// themselves change.
pub(crate) const SCHEMA_VERSION: i32 = 1;

/// Permission bits a new database file is created with: it holds password
/// hashes, TOTP secrets and the enrollment token.
const DB_FILE_MODE: u32 = 0o600;

/// A [`CaStore`] over one SQLite database.
pub(crate) struct SqliteStore {
    conn: rusqlite::Connection,
}

impl SqliteStore {
    /// Open (creating if absent) the database at `path`, bringing its tables up
    /// to [`SCHEMA_VERSION`]. A database written by a newer build is refused.
    ///
    /// The file is created owner-only *before* SQLite opens it, so there is no
    /// moment it exists with the umask's mode. SQLite gives its `-wal` and
    /// `-shm` files the database's own permissions.
    pub(crate) fn open(path: &std::path::Path) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(DB_FILE_MODE)
            .open(path)
            .map_err(|e| format!("cannot create CA database {}: {e}", path.display()))?;
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("cannot open CA database {}: {e}", path.display()))?;
        // WAL so a management read never waits on a write, and FULL so a
        // committed revocation or issuance survives power loss: this is the
        // root of trust, and its write rate is an operator's, not a packet's.
        conn.pragma_update(None, "journal_mode", "WAL")
            .and_then(|()| conn.pragma_update(None, "synchronous", "FULL"))
            .map_err(|e| format!("cannot configure CA database {}: {e}", path.display()))?;
        Self::with_connection(conn)
    }

    /// An empty database held in memory, for tests.
    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self, String> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| format!("cannot open in-memory database: {e}"))?;
        Self::with_connection(conn)
    }

    fn with_connection(mut conn: rusqlite::Connection) -> Result<Self, String> {
        migrate(&mut conn)?;
        Ok(Self { conn })
    }
}

/// Bring `conn`'s tables up to [`SCHEMA_VERSION`], in one transaction.
fn migrate(conn: &mut rusqlite::Connection) -> Result<(), String> {
    let err = |e: rusqlite::Error| format!("CA database migration failed: {e}");
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(err)?;
    if version > SCHEMA_VERSION {
        return Err(format!(
            "CA database has table layout {version}, newer than this build's \
             {SCHEMA_VERSION}; refusing to read it rather than guess at its meaning"
        ));
    }
    let tx = conn.transaction().map_err(err)?;
    if version < 1 {
        tx.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE records (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 collection TEXT NOT NULL,
                 body BLOB NOT NULL
             );
             CREATE INDEX records_by_collection ON records (collection);",
        )
        .map_err(err)?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(err)?;
    tx.commit().map_err(err)
}

impl CaStore for SqliteStore {
    fn load(&mut self) -> Result<Loaded, String> {
        let err = |e: rusqlite::Error| format!("cannot read CA database: {e}");
        let initialized = self
            .conn
            .query_row("SELECT 1 FROM meta WHERE key = 'initialized'", [], |_| {
                Ok(())
            })
            .map(|()| true)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                e => Err(err(e)),
            })?;
        let mut stmt = self
            .conn
            .prepare("SELECT id, collection, body FROM records")
            .map_err(err)?;
        let mut rows = Vec::new();
        let mut query = stmt.query([]).map_err(err)?;
        while let Some(row) = query.next().map_err(err)? {
            let id: i64 = row.get(0).map_err(err)?;
            let name: String = row.get(1).map_err(err)?;
            let body: Vec<u8> = row.get(2).map_err(err)?;
            // Fail closed on a collection this build does not know: skipping
            // it would silently drop records a newer build wrote, and the next
            // write would never know they were there.
            let collection = Collection::parse(&name)
                .ok_or_else(|| format!("CA database row {id} is in unknown collection {name:?}"))?;
            rows.push(Row {
                collection,
                id,
                body,
            });
        }
        Ok(Loaded { initialized, rows })
    }

    fn commit(&mut self, change: &ChangeSet) -> Result<Vec<i64>, String> {
        let err = |e: rusqlite::Error| format!("cannot write CA database: {e}");
        let tx = self.conn.transaction().map_err(err)?;
        for (collection, id) in &change.deletes {
            let deleted = tx
                .execute(
                    "DELETE FROM records WHERE id = ?1 AND collection = ?2",
                    rusqlite::params![id, collection.as_str()],
                )
                .map_err(err)?;
            if deleted != 1 {
                // Dropping `tx` rolls back everything before this point.
                return Err(format!(
                    "CA database has no row {id} in {}; the store and the \
                     authority's view of it have diverged",
                    collection.as_str()
                ));
            }
        }
        let mut ids = Vec::with_capacity(change.inserts.len());
        for (collection, body) in &change.inserts {
            tx.execute(
                "INSERT INTO records (collection, body) VALUES (?1, ?2)",
                rusqlite::params![collection.as_str(), body],
            )
            .map_err(err)?;
            ids.push(tx.last_insert_rowid());
        }
        tx.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('initialized', '1')",
            [],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(ids)
    }
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
