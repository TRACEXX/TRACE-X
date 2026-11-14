import re


def linear_search(items, predicate, steps=None):
    """Return every item for which predicate(item) is True."""
    matches = []
    for index, item in enumerate(items):
        hit = predicate(item)
        if steps is not None:
            steps.append(f"Check item {index}: {'match' if hit else 'no match'}")
        if hit:
            matches.append(item)
    return matches


def binary_search(sorted_items, target, key=lambda item: item, steps=None):
    """Find `target` in a list sorted by key(item). Returns the index or -1."""
    low = 0
    high = len(sorted_items) - 1
    while low <= high:
        mid = (low + high) // 2
        mid_value = key(sorted_items[mid])
        if steps is not None:
            steps.append(f"low={low}, high={high}, mid={mid} -> compare '{mid_value}' with '{target}'")
        if mid_value == target:
            return mid
        if mid_value < target:
            low = mid + 1          
        else:
            high = mid - 1         
    return -1


def tokenize(text):
    """Split text into lowercase words and numbers."""
    return re.findall(r"[a-z0-9]+", (text or "").lower())


def keyword_search(records, query, fields, weights=None):
    """Score every record against the words in `query`.

    records : list of dicts
    fields  : which keys to look in
    weights : optional {field: weight}, e.g. a hit in the title counts more
    Returns a list of (score, record) for records with score > 0.
    """
    words = [w for w in tokenize(query) if len(w) > 1]
    if not words:
        return []
    weights = weights or {}
    results = []
    for record in records:
        score = 0
        for field in fields:
            value = str(record.get(field) or "").lower()
            if not value:
                continue
            for word in words:
                if word in value:
                    score += weights.get(field, 1)
        if score > 0:
            results.append((score, record))
    return results
