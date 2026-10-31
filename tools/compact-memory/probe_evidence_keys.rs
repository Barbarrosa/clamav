// SPDX-License-Identifier: GPL-2.0-only
// Isolated allocation-count and exact-history comparison of the two key paths.
// Link the engine's pinned indexmap rlib; no additional dependency or codec.
use indexmap::{map::RawEntryApiV1, IndexMap};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

struct Counting;
static ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ENABLED.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size(), Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) { System.dealloc(p, layout); }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if ENABLED.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(size, Relaxed);
        }
        System.realloc(p, layout, size)
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measure(map: &mut IndexMap<String, Vec<[usize; 3]>>, names: &[String], borrowed: bool, repeat: usize) -> (usize, usize) {
    ALLOCS.store(0, Relaxed); BYTES.store(0, Relaxed); ENABLED.store(true, Relaxed);
    for i in 0..repeat {
        let name = names[i % names.len()].as_str();
        let meta = [i, i % 31, i % 127];
        if borrowed {
            map.raw_entry_mut_v1().from_key(name)
                .or_insert_with(|| (name.to_owned(), Vec::new())).1.push(meta);
        } else {
            map.entry(name.to_owned()).or_default().push(meta);
        }
    }
    ENABLED.store(false, Relaxed);
    (ALLOCS.load(Relaxed), BYTES.load(Relaxed))
}

fn main() {
    for (scenario, unique, repeat, warm) in [("repeated", 1, 100_000, true), ("distinct", 10_000, 10_000, false), ("mixed", 100, 100_000, false)] {
        let names: Vec<_> = (0..unique).map(|i| format!("Foundations.Evidence.Name.{i:08}" )).collect();
        let mut before = IndexMap::new(); let mut after = IndexMap::new();
        if warm {
            for name in &names {
                before.insert(name.clone(), Vec::with_capacity(repeat));
                after.insert(name.clone(), Vec::with_capacity(repeat));
            }
        }
        let old = measure(&mut before, &names, false, repeat);
        let new = measure(&mut after, &names, true, repeat);
        assert!(before.iter().eq(after.iter()));
        assert_eq!(old.0 - new.0, if warm { repeat } else { repeat - unique });
        if scenario == "distinct" { assert_eq!(old, new); }
        println!("{{\"scenario\":\"{}\",\"events\":{},\"distinct_names\":{},\"before_allocations\":{},\"after_allocations\":{},\"before_requested_bytes\":{},\"after_requested_bytes\":{},\"ordered_history_equal\":true}}", scenario, repeat, unique, old.0, new.0, old.1, new.1);
    }
}
