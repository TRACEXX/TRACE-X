def merge_sort(items, key=lambda item: item, reverse=False, steps=None):
    """Return a new sorted list. The input list is not changed."""
    items = list(items)
    if len(items) <= 1:                      
        return items
    middle = len(items) // 2
    left = merge_sort(items[:middle], key, reverse, steps)
    right = merge_sort(items[middle:], key, reverse, steps)
    merged = _merge(left, right, key, reverse)
    if steps is not None:
        steps.append(
            f"merge {[_short(key(x)) for x in left]} + {[_short(key(x)) for x in right]}"
            f" -> {[_short(key(x)) for x in merged]}")
    return merged


def _merge(left, right, key, reverse):
    result = []
    i = j = 0
    while i < len(left) and j < len(right):
        a, b = key(left[i]), key(right[j])
        # "<=" (or ">=") keeps the sort stable: ties come from the left half first.
        take_left = a >= b if reverse else a <= b
        if take_left:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    result.extend(left[i:])                    
    result.extend(right[j:])
    return result


def _short(value):
    text = str(value)
    return text if len(text) <= 19 else text[:19]
