class _QueueNode:
    def __init__(self, data):
        self.data = data
        self.next = None


class Queue:
    def __init__(self):
        self._front = None
        self._rear = None
        self._size = 0

    def enqueue(self, item):
        """Add an item at the rear."""
        node = _QueueNode(item)
        if self._rear is None:
            self._front = node
            self._rear = node
        else:
            self._rear.next = node
            self._rear = node
        self._size += 1

    def dequeue(self):
        """Remove and return the front item. Raises IndexError when empty."""
        if self._front is None:
            raise IndexError("dequeue from an empty queue")
        item = self._front.data
        self._front = self._front.next
        if self._front is None:        
            self._rear = None
        self._size -= 1
        return item

    def peek(self):
        return None if self._front is None else self._front.data

    def is_empty(self):
        return self._front is None

    def to_list(self):
        items = []
        node = self._front
        while node is not None:
            items.append(node.data)
            node = node.next
        return items

    def __len__(self):
        return self._size
