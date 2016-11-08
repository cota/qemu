===
QHT
===

QEMU Hash Table, designed to scale.

Assumptions
-----------
- NULL cannot be inserted/removed as a pointer value.
- Trying to insert an already-existing hash-pointer pair is OK. However,
  it is not OK to insert into the same hash table different hash-pointer
  pairs that have the same pointer value, but not the hashes.
- Lookups are performed under an RCU read-critical section; removals
  must wait for a grace period to elapse before freeing removed objects.

Features
--------
- Reads (i.e. lookups and iterators) can be concurrent with other reads.
  Lookups that are concurrent with writes to the same bucket will retry
  via a seqlock; iterators acquire all bucket locks and therefore can be
  concurrent with lookups and are serialized wrt writers.
- Writes (i.e. insertions/removals) can be concurrent with writes to
  different buckets; writes to the same bucket are serialized through a lock.
- Optional auto-resizing: the hash table resizes up if the load surpasses
  a certain threshold. Resizing is done concurrently with readers; writes
  are serialized with the resize operation.

Internals
---------
The key structure is the **bucket**, which is cacheline-sized. Buckets
contain a few hash values and pointers; the ``u32`` hash values are stored in
full so that resizing is fast. Having this structure instead of directly
chaining items has two advantages:

- Failed lookups fail fast, and touch a minimum number of cache lines.
- Resizing the hash table with concurrent lookups is easy.

There are two types of buckets:

1. **head** buckets are the ones allocated in the array of buckets in ``qht_map``.
2. all **non-head** buckets (i.e. all others) are members of a chain that
   starts from a head bucket.

Note that the *seqlock* and *spinlock* of a head bucket applies to all buckets
chained to it; these two fields are unused in non-head buckets.

On removals, we move the last valid item in the chain to the position of the
just-removed entry. This makes lookups slightly faster, since the moment an
invalid entry is found, the (failed) lookup is over.

Resizing is done by taking all bucket spinlocks (so that no other writers can
race with us) and then copying all entries into a new hash map. Then, the
``ht->map`` pointer is set, and the old map is freed once no RCU readers can see
it anymore.

Writers check for concurrent resizes by comparing ``ht->map`` before and after
acquiring their bucket lock. If they don't match, a resize has occured
while the bucket spinlock was being acquired.

Related Work
------------
- Idea of cacheline-sized buckets with full hashes taken from:
  `The Secret to Scaling Concurrent Search Data Structures
  <http://dl.acm.org/citation.cfm?doid=2775054.2694359>`_
  (ASPLOS'15) by David, Guerraoui & Trigonakis.

- Why not RCU-based hash tables? They would allow us to get rid of the
  seqlock, but resizing would take forever since RCU read critical
  sections in QEMU take quite a long time.

  More info on relativistic hash tables:

  - `Resizable, Scalable, Concurrent Hash Tables via Relativistic Programming
    <https://www.usenix.org/legacy/event/atc11/tech/final_files/Triplett.pdf>`_
    (USENIX ATC'11) by Triplett, McKenney & Walpole.
  - `Relativistic hash tables, part 1: Algorithms
    <https://lwn.net/Articles/612021/>`_ by Corbet.

API Documentation
-----------------
.. kernel-doc:: include/qemu/qht.h
