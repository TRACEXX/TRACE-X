class _StackNode:
    def __init__(self, data, below):
        self.data = data
        self.below = below


class Stack:
    def __init__(self):
        self._top = None
        self._size = 0

    def push(self, item):
        """Put an item on top of the stack."""
        self._top = _StackNode(item, self._top)
        self._size += 1

    def pop(self):
        """Remove and return the top item. Raises IndexError when empty."""
        if self._top is None:
            raise IndexError("pop from an empty stack")
        item = self._top.data
        self._top = self._top.below
        self._size -= 1
        return item

    def peek(self):
        """Return the top item without removing it (None when empty)."""
        return None if self._top is None else self._top.data

    def is_empty(self):
        return self._top is None

    def to_list(self):
        """Items from top to bottom (useful for displaying the stack)."""
        items = []
        node = self._top
        while node is not None:
            items.append(node.data)
            node = node.below
        return items

    def __len__(self):
        return self._size
