"""
Hash table with separate chaining.

Used to INDEX EVIDENCE by evidence ID (e.g. 'EV-0007') so a record can be
found without scanning every evidence row.

How it works:
  1. A hash function turns the key into a number.
  2. number % capacity picks a bucket.
  3. Each bucket is a list of [key, value] pairs. Two keys that land in the
     same bucket (a COLLISION) are simply stored side by side in that list.
  4. When the table gets more than 75% full it doubles in size (resize) so the
     chains stay short.

Average complexity: put O(1), get O(1). Worst case (all keys collide) O(n).
"""


class HashTable:
    LOAD_FACTOR_LIMIT = 0.75

    def __init__(self, capacity=8):
        self.capacity = capacity
        self.buckets = [[] for _ in range(capacity)]
        self.count = 0
        self.collisions = 0
        self.resizes = 0

    def _hash(self, key):
        """Polynomial rolling hash: h = h * 31 + character code (kept to 32 bits)."""
        h = 0
        for character in str(key):
            h = (h * 31 + ord(character)) % (2 ** 32)
        return h

    def bucket_index(self, key):
        return self._hash(key) % self.capacity

    def put(self, key, value):
        """Insert or update a key. Returns the bucket index used."""
        index = self.bucket_index(key)
        bucket = self.buckets[index]
        for pair in bucket:
            if pair[0] == key:          # key already present: update it
                pair[1] = value
                return index
        if bucket:                      # bucket already holds other keys
            self.collisions += 1
        bucket.append([key, value])
        self.count += 1
        if self.count / self.capacity > self.LOAD_FACTOR_LIMIT:
            self._resize()
            index = self.bucket_index(key)
        return index

    def get(self, key, default=None):
        value, _, _ = self.get_with_trace(key)
        return default if value is None else value

    def get_with_trace(self, key):
        """Look up a key and also report which bucket was searched and how
        many comparisons were needed (shown on the DSA Inspector page)."""
        index = self.bucket_index(key)
        comparisons = 0
        for stored_key, value in self.buckets[index]:
            comparisons += 1
            if stored_key == key:
                return value, index, comparisons
        return None, index, comparisons

    def remove(self, key):
        index = self.bucket_index(key)
        bucket = self.buckets[index]
        for position, pair in enumerate(bucket):
            if pair[0] == key:
                del bucket[position]
                self.count -= 1
                return True
        return False

    def _resize(self):
        """Double the capacity and re-insert every pair into the new buckets."""
        old_pairs = self.items()
        self.capacity *= 2
        self.buckets = [[] for _ in range(self.capacity)]
        self.count = 0
        self.collisions = 0
        self.resizes += 1
        for key, value in old_pairs:
            index = self.bucket_index(key)
            if self.buckets[index]:
                self.collisions += 1
            self.buckets[index].append([key, value])
            self.count += 1

    def keys(self):
        return [pair[0] for bucket in self.buckets for pair in bucket]

    def items(self):
        return [(pair[0], pair[1]) for bucket in self.buckets for pair in bucket]

    def bucket_report(self):
        """List of (bucket index, [keys in that bucket]) for display."""
        return [(i, [pair[0] for pair in bucket]) for i, bucket in enumerate(self.buckets)]

    def __contains__(self, key):
        return self.get_with_trace(key)[0] is not None

    def __len__(self):
        return self.count
