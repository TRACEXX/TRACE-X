"""
Singly linked list.

Used for the evidence CHAIN OF CUSTODY: every custody event (registered,
viewed, verified, downloaded, transferred ...) is one node, and each node
points to the event that happened after it. Reading the list from head to
tail gives the handling history in order.

    head -> [Registered] -> [Viewed] -> [Verified] -> None
                                              ^ tail

Complexity:
    append   O(1)  (we keep a tail pointer)
    traverse O(n)
    search   O(n)  (linear search, the list is not indexed)
"""


class Node:
    def __init__(self, data):
        self.data = data
        self.next = None


class LinkedList:
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def append(self, data):
        """Add a new event at the end of the chain."""
        node = Node(data)
        if self.head is None:          # empty list: node is both head and tail
            self.head = node
            self.tail = node
        else:
            self.tail.next = node      # link the old last node to the new one
            self.tail = node
        self.size += 1
        return node

    def traverse(self):
        """Yield every item from head to tail."""
        current = self.head
        while current is not None:
            yield current.data
            current = current.next

    def search(self, predicate):
        """Return (position, item) of the first item where predicate(item) is True.

        Returns (-1, None) when nothing matches.
        """
        position = 0
        current = self.head
        while current is not None:
            if predicate(current.data):
                return position, current.data
            current = current.next
            position += 1
        return -1, None

    def search_all(self, predicate):
        """Return every item for which predicate(item) is True."""
        return [item for item in self.traverse() if predicate(item)]

    def to_list(self):
        return list(self.traverse())

    def display(self, formatter=str):
        """Text picture of the list, e.g. 'A -> B -> C -> None'."""
        parts = [formatter(item) for item in self.traverse()]
        return " -> ".join(parts + ["None"])

    def __len__(self):
        return self.size

    def __iter__(self):
        return self.traverse()
