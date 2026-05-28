use heapless::index_map::FnvIndexMap;
pub use interfaces;

use interfaces::frame::MeshIdentifier;

/// Sentinel value meaning "no node" in the LRU linked list.
/// Valid slot indices are 0..IDENT_TABLE_MAX (at most 99), so 255 is safe.
const NONE_IDX: u8 = u8::MAX;
/// `heapless::FnvIndexMap` requires a power-of-two capacity.
const IDENT_TABLE_CAP: usize = 128;
/// Actual maximum live entries before LRU eviction kicks in.
const IDENT_TABLE_MAX: usize = 100;

/// A node in the doubly-linked LRU list, stored in the flat node pool.
///
/// `prev` points toward the MRU head; `next` points toward the LRU tail.
/// Both use `NONE_IDX` as a null pointer.
#[derive(Clone, Copy)]
struct LruNode<Ident> {
    key: Ident,
    iface_idx: usize,
    prev: u8,
    next: u8,
}

/// Maps mesh identifiers to egress interfaces with **O(1)** insert, lookup,
/// and eviction via a fixed-capacity LRU cache.
///
/// ### Data structure
/// - **Node pool** (`nodes`): a flat array of `Option<LruNode>` slots.
/// - **Hash map** (`map`): `Ident → slot index`, giving O(1) key lookup.
/// - **Doubly-linked list** (intrusive, through `prev`/`next` in each node):
///   head = MRU, tail = LRU.  Move-to-front and evict-tail are both O(1).
/// - **Free-slot stack** (`free_stack`/`free_len`): O(1) slot allocation.
///
/// At most `IDENT_TABLE_MAX` (100) live entries are kept.  When the table is
/// full and a new identifier arrives, the tail (LRU entry) is evicted in O(1).
/// The underlying heapless map is sized to `IDENT_TABLE_CAP` (128) because
/// `FnvIndexMap` requires a power-of-two capacity.
pub struct IdentTable<Ident: MeshIdentifier> {
    /// Flat node pool; slots whose index is in `free_stack` are unoccupied.
    nodes: [Option<LruNode<Ident>>; IDENT_TABLE_CAP],
    /// Key → slot index in `nodes`.
    map: FnvIndexMap<Ident, u8, IDENT_TABLE_CAP>,
    /// Index of the most-recently-used node; `NONE_IDX` when the table is empty.
    head: u8,
    /// Index of the least-recently-used node; `NONE_IDX` when the table is empty.
    tail: u8,
    /// Stack of available slot indices.
    free_stack: [u8; IDENT_TABLE_CAP],
    /// Number of entries in `free_stack`.
    free_len: u8,
}

impl<Ident: MeshIdentifier> IdentTable<Ident> {
    pub fn new() -> Self {
        let mut free_stack = [0u8; IDENT_TABLE_CAP];
        for i in 0..IDENT_TABLE_CAP {
            free_stack[i] = i as u8;
        }
        Self {
            nodes: core::array::from_fn(|_| None),
            map: FnvIndexMap::new(),
            head: NONE_IDX,
            tail: NONE_IDX,
            free_stack,
            // Only vend the first IDENT_TABLE_MAX slots; the remaining
            // IDENT_TABLE_CAP - IDENT_TABLE_MAX slots act as unused padding
            // required by the power-of-two heapless capacity.
            free_len: IDENT_TABLE_MAX as u8,
        }
    }

    // ── linked-list helpers ──────────────────────────────────────────────────

    /// Remove node `idx` from the doubly-linked list.  O(1).
    fn unlink(&mut self, idx: u8) {
        // `LruNode` is `Copy`, so `.unwrap()` gives us a value, not a reference,
        // keeping the borrow of `self.nodes` trivially short.
        let node = self.nodes[idx as usize].unwrap();
        if node.prev != NONE_IDX {
            self.nodes[node.prev as usize].as_mut().unwrap().next = node.next;
        } else {
            self.head = node.next;
        }
        if node.next != NONE_IDX {
            self.nodes[node.next as usize].as_mut().unwrap().prev = node.prev;
        } else {
            self.tail = node.prev;
        }
    }

    /// Insert node `idx` at the MRU head of the list.  O(1).
    ///
    /// The slot must already be populated in `self.nodes` but not yet linked.
    fn link_at_head(&mut self, idx: u8) {
        let old_head = self.head;

        // Update the new head's own pointers (copy-modify-store).
        let mut node = self.nodes[idx as usize].unwrap();
        node.prev = NONE_IDX;
        node.next = old_head;
        self.nodes[idx as usize] = Some(node);

        if old_head != NONE_IDX {
            self.nodes[old_head as usize].as_mut().unwrap().prev = idx;
        } else {
            // List was empty; this node is also the tail.
            self.tail = idx;
        }
        self.head = idx;
    }

    /// Move an already-linked node to the MRU head.  O(1).
    fn move_to_front(&mut self, idx: u8) {
        if self.head == idx {
            return;
        }
        self.unlink(idx);
        self.link_at_head(idx);
    }

    // ── public interface ─────────────────────────────────────────────────────

    /// Record (or refresh) the egress interface for `dest`.
    ///
    /// If the table is at capacity and `dest` is not yet known, the
    /// least-recently-used entry is evicted in O(1) to make room.
    pub fn add_record(&mut self, iface_idx: usize, dest: Ident) {
        if let Some(&idx) = self.map.get(&dest) {
            // Refresh existing entry.
            self.nodes[idx as usize].as_mut().unwrap().iface_idx = iface_idx;
            self.move_to_front(idx);
            return;
        }

        // New destination — obtain a free slot.
        let slot = if self.free_len > 0 {
            // Pop from the free stack.
            self.free_len -= 1;
            self.free_stack[self.free_len as usize]
        } else {
            // Table is full: evict the LRU tail in O(1).
            let lru_idx = self.tail;
            let lru_key = self.nodes[lru_idx as usize].unwrap().key;
            self.map.remove(&lru_key);
            self.unlink(lru_idx);
            lru_idx
        };

        self.nodes[slot as usize] = Some(LruNode {
            key: dest,
            iface_idx,
            prev: NONE_IDX,
            next: NONE_IDX,
        });
        let _ = self.map.insert(dest, slot);
        self.link_at_head(slot);
    }

    /// Return the interface index for `dest`, refreshing its recency.  O(1).
    pub fn get_egress_interface(&mut self, dest: Ident) -> Option<usize> {
        let idx = *self.map.get(&dest)?;
        self.move_to_front(idx);
        Some(self.nodes[idx as usize].unwrap().iface_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `u8` implements `MeshIdentifier`, so it's the natural choice for tests.

    // ── invariant checker ────────────────────────────────────────────────────

    impl<Ident: MeshIdentifier> IdentTable<Ident> {
        /// Walk the doubly-linked list in both directions and assert internal
        /// consistency.  Panics on any violation — call this liberally in tests.
        fn assert_invariants(&self) {
            // Forward walk: head → tail
            let mut forward: std::vec::Vec<u8> = std::vec::Vec::new();
            let mut cur = self.head;
            let mut expected_prev = NONE_IDX;
            while cur != NONE_IDX {
                let node = self.nodes[cur as usize].expect("linked-list node slot is None");
                assert_eq!(
                    node.prev, expected_prev,
                    "node {cur}: prev should be {expected_prev} but is {}",
                    node.prev
                );
                forward.push(cur);
                expected_prev = cur;
                cur = node.next;
            }
            assert_eq!(
                expected_prev,
                self.tail,
                "tail pointer {tail} doesn't match last forward-walk node {expected_prev}",
                tail = self.tail
            );

            // Backward walk: tail → head
            let mut backward: std::vec::Vec<u8> = std::vec::Vec::new();
            let mut cur = self.tail;
            let mut expected_next = NONE_IDX;
            while cur != NONE_IDX {
                let node = self.nodes[cur as usize].unwrap();
                assert_eq!(
                    node.next, expected_next,
                    "node {cur}: next should be {expected_next} but is {}",
                    node.next
                );
                backward.push(cur);
                expected_next = cur;
                cur = node.prev;
            }
            assert_eq!(
                expected_next,
                self.head,
                "head pointer {head} doesn't match last backward-walk node {expected_next}",
                head = self.head
            );

            // Both walks must cover exactly the entries in the map.
            assert_eq!(
                forward.len(),
                self.map.len(),
                "forward walk length {} != map length {}",
                forward.len(),
                self.map.len()
            );

            backward.reverse();
            assert_eq!(forward, backward, "forward and backward walks disagree");

            // Every map value must point at an occupied, matching node.
            for (key, &slot) in self.map.iter() {
                let node = self.nodes[slot as usize].expect("map slot points to a None node");
                assert_eq!(&node.key, key, "node key mismatch for slot {slot}");
            }

            // free_len + map.len() == IDENT_TABLE_MAX
            assert_eq!(
                self.free_len as usize + self.map.len(),
                IDENT_TABLE_MAX,
                "free_len + map.len() should equal IDENT_TABLE_MAX"
            );
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Return the LRU order as a Vec of keys, MRU-first.
    fn lru_order(table: &IdentTable<u8>) -> std::vec::Vec<u8> {
        let mut order = std::vec::Vec::new();
        let mut cur = table.head;
        while cur != NONE_IDX {
            let node = table.nodes[cur as usize].unwrap();
            order.push(node.key);
            cur = node.next;
        }
        order
    }

    // ── basic correctness ────────────────────────────────────────────────────

    #[test]
    fn empty_table_returns_none() {
        let mut table = IdentTable::<u8>::new();
        assert_eq!(table.get_egress_interface(42), None);
        assert_eq!(table.head, NONE_IDX);
        assert_eq!(table.tail, NONE_IDX);
        assert_eq!(table.free_len, IDENT_TABLE_MAX as u8);
        table.assert_invariants();
    }

    #[test]
    fn insert_and_lookup() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(3, 42);
        assert_eq!(table.get_egress_interface(42), Some(3));
        table.assert_invariants();
    }

    #[test]
    fn unknown_key_returns_none() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(0, 10);
        assert_eq!(table.get_egress_interface(99), None);
    }

    #[test]
    fn update_iface_for_existing_key() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(0, 1);
        table.add_record(5, 1); // same key, different interface
        assert_eq!(table.get_egress_interface(1), Some(5));
        assert_eq!(table.map.len(), 1, "no duplicate entry should be created");
        table.assert_invariants();
    }

    // ── single-entry edge case ───────────────────────────────────────────────

    #[test]
    fn single_entry_head_equals_tail() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(7, 42);
        assert_eq!(table.head, table.tail, "single entry: head must equal tail");
        let node = table.nodes[table.head as usize].unwrap();
        assert_eq!(node.prev, NONE_IDX);
        assert_eq!(node.next, NONE_IDX);
        table.assert_invariants();
    }

    // ── LRU ordering ─────────────────────────────────────────────────────────

    #[test]
    fn insertion_order_is_mru_first() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(0, 10);
        table.add_record(1, 20);
        table.add_record(2, 30);
        // 30 was inserted last → MRU head; 10 was inserted first → LRU tail
        assert_eq!(lru_order(&table), [30, 20, 10]);
        table.assert_invariants();
    }

    #[test]
    fn read_moves_entry_to_front() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(0, 10);
        table.add_record(1, 20);
        table.add_record(2, 30);
        // order: [30, 20, 10]
        let _ = table.get_egress_interface(10); // promote 10 to MRU
        assert_eq!(lru_order(&table), [10, 30, 20]);
        table.assert_invariants();
    }

    #[test]
    fn write_update_moves_entry_to_front() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(0, 10);
        table.add_record(1, 20);
        table.add_record(2, 30);
        // order: [30, 20, 10]
        table.add_record(9, 10); // re-insert 10 with new iface → MRU
        assert_eq!(lru_order(&table), [10, 30, 20]);
        assert_eq!(table.get_egress_interface(10), Some(9));
        table.assert_invariants();
    }

    #[test]
    fn move_middle_entry_to_front() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(0, 10);
        table.add_record(1, 20);
        table.add_record(2, 30);
        // order: [30, 20, 10]
        let _ = table.get_egress_interface(20); // promote middle entry
        // 30's prev should now point to 20; 10's next should be NONE_IDX
        assert_eq!(lru_order(&table), [20, 30, 10]);
        table.assert_invariants();
    }

    #[test]
    fn read_already_at_head_is_noop() {
        let mut table = IdentTable::<u8>::new();
        table.add_record(0, 10);
        table.add_record(1, 20);
        table.add_record(2, 30); // 30 is MRU
        let _ = table.get_egress_interface(30); // already at head
        assert_eq!(lru_order(&table), [30, 20, 10]);
        table.assert_invariants();
    }

    // ── eviction ─────────────────────────────────────────────────────────────

    #[test]
    fn eviction_removes_lru_entry() {
        let mut table = IdentTable::<u8>::new();
        // Fill all 100 slots with keys 0..100.
        for i in 0u8..100 {
            table.add_record(i as usize, i);
        }
        assert_eq!(table.map.len(), 100);
        table.assert_invariants();

        // Key 0 was inserted first → LRU.  Adding key 100 must evict it.
        table.add_record(100, 100u8);
        assert_eq!(
            table.get_egress_interface(0),
            None,
            "key 0 should be evicted"
        );
        assert_eq!(table.get_egress_interface(100), Some(100));
        assert_eq!(table.map.len(), 100, "capacity should remain at 100");
        table.assert_invariants();
    }

    #[test]
    fn recent_read_protects_entry_from_eviction() {
        let mut table = IdentTable::<u8>::new();
        for i in 0u8..100 {
            table.add_record(i as usize, i);
        }
        // Promote key 0 to MRU — now key 1 is the LRU.
        let _ = table.get_egress_interface(0);
        table.add_record(101, 101u8); // should evict key 1
        assert_eq!(
            table.get_egress_interface(0),
            Some(0),
            "key 0 was recently read, must not be evicted"
        );
        assert_eq!(
            table.get_egress_interface(1),
            None,
            "key 1 should be evicted"
        );
        assert_eq!(table.get_egress_interface(101), Some(101));
        table.assert_invariants();
    }

    #[test]
    fn recent_write_protects_entry_from_eviction() {
        let mut table = IdentTable::<u8>::new();
        for i in 0u8..100 {
            table.add_record(i as usize, i);
        }
        // Re-inserting key 0 with a new interface makes it MRU → key 1 becomes LRU.
        table.add_record(99, 0u8);
        table.add_record(101, 101u8); // should evict key 1
        assert_eq!(
            table.get_egress_interface(0),
            Some(99),
            "key 0 updated, must not be evicted"
        );
        assert_eq!(
            table.get_egress_interface(1),
            None,
            "key 1 should be evicted"
        );
        table.assert_invariants();
    }

    #[test]
    fn sequential_evictions_maintain_order() {
        let mut table = IdentTable::<u8>::new();
        for i in 0u8..100 {
            table.add_record(i as usize, i);
        }
        // Each new insert evicts the oldest surviving key in order.
        table.add_record(100, 100u8); // evicts 0
        table.add_record(101, 101u8); // evicts 1
        table.add_record(102, 102u8); // evicts 2

        assert_eq!(table.get_egress_interface(0), None);
        assert_eq!(table.get_egress_interface(1), None);
        assert_eq!(table.get_egress_interface(2), None);
        assert_eq!(
            table.get_egress_interface(3),
            Some(3),
            "key 3 should still be present"
        );
        assert_eq!(table.map.len(), 100);
        table.assert_invariants();
    }
}
