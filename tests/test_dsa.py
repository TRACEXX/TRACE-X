"""Unit tests for the hand-written data structures and algorithms in dsa/."""

import random

import pytest

from dsa.graph import Graph
from dsa.hash_table import HashTable
from dsa.linked_list import LinkedList
from dsa.queue import Queue
from dsa.searching import binary_search, keyword_search, linear_search
from dsa.sorting import merge_sort
from dsa.stack import Stack
from dsa.tree import TreeNode, build_evidence_tree


def test_linked_list_append_traverse_search():
    chain = LinkedList()
    for action in ("registered", "viewed", "verified", "viewed"):
        chain.append({"action": action})
    assert len(chain) == 4
    assert [e["action"] for e in chain.traverse()] == ["registered", "viewed", "verified", "viewed"]
    assert chain.search(lambda e: e["action"] == "verified") == (2, {"action": "verified"})
    assert chain.search(lambda e: e["action"] == "deleted") == (-1, None)
    assert len(chain.search_all(lambda e: e["action"] == "viewed")) == 2
    assert chain.display(lambda e: e["action"]).endswith("viewed -> None")


def test_stack_is_lifo():
    stack = Stack()
    for version in ("v1", "v2", "v3"):
        stack.push(version)
    assert stack.peek() == "v3"
    assert [stack.pop(), stack.pop()] == ["v3", "v2"]
    assert len(stack) == 1 and not stack.is_empty()
    stack.pop()
    with pytest.raises(IndexError):
        stack.pop()


def test_queue_is_fifo():
    queue = Queue()
    for task in ("A", "B", "C"):
        queue.enqueue(task)
    assert queue.to_list() == ["A", "B", "C"]
    assert queue.dequeue() == "A"
    queue.enqueue("D")
    assert [queue.dequeue(), queue.dequeue(), queue.dequeue()] == ["B", "C", "D"]
    assert queue.is_empty()
    with pytest.raises(IndexError):
        queue.dequeue()


def test_hash_table_put_get_collisions_and_resize():
    table = HashTable(capacity=2)
    codes = [f"EV-{i:04d}" for i in range(1, 41)]
    for code in codes:
        table.put(code, {"code": code})
    assert len(table) == 40
    assert table.resizes > 0 and table.capacity >= 64
    for code in codes:
        assert table.get(code)["code"] == code
    value, bucket, comparisons = table.get_with_trace("EV-0007")
    assert value["code"] == "EV-0007" and 0 <= bucket < table.capacity and comparisons >= 1
    table.put("EV-0007", {"code": "updated"})
    assert table.get("EV-0007")["code"] == "updated" and len(table) == 40
    assert table.remove("EV-0007") and "EV-0007" not in table
    assert table.get("missing") is None


def test_hash_table_handles_forced_collisions():
    table = HashTable(capacity=1000)
    table.capacity = 1                      # every key in one bucket: pure chaining
    table.buckets = [[]]
    for key in ("a", "b", "c"):
        table.buckets[0].append([key, key.upper()])
    assert table.get_with_trace("c") == ("C", 0, 3)


def test_tree_recursion():
    cases = [{"id": 1, "case_number": "CASE-001", "title": "A"}, {"id": 2, "case_number": "CASE-002", "title": "B"}]
    evidence = [
        {"id": 10, "case_id": 1, "evidence_code": "EV-0010", "filename": "a.png", "file_type": "image"},
        {"id": 11, "case_id": 1, "evidence_code": "EV-0011", "filename": "b.csv", "file_type": "csv"},
        {"id": 12, "case_id": 1, "evidence_code": "EV-0012", "filename": "c.png", "file_type": "image"},
        {"id": 13, "case_id": 2, "evidence_code": "EV-0013", "filename": "d.txt", "file_type": "text"},
    ]
    root = build_evidence_tree(cases, evidence)
    # root + 2 cases + 3 folders + 4 files
    assert root.count() == 10
    assert root.height() == 3
    found = root.find(lambda n: n.kind == "evidence" and n.ref == 13)
    assert found is not None and "d.txt" in found.name
    depths = [depth for depth, _ in root.preorder()]
    assert depths[0] == 0 and max(depths) == 3
    assert "├──" in root.render()
    assert TreeNode("leaf", "evidence").to_dict()["children"] == []


def _sample_graph():
    #   S1 - E1 - L1 - W1
    #    \
    #     E2 - D1          X (isolated)
    graph = Graph()
    for a, b in [("S1", "E1"), ("E1", "L1"), ("L1", "W1"), ("S1", "E2"), ("E2", "D1")]:
        graph.add_edge(a, b, {"id": a + b, "type": "link", "description": f"{a}-{b}"})
    graph.add_node("X")
    return graph


def test_bfs_visits_by_distance():
    order, distance = _sample_graph().bfs("S1")
    assert order == ["S1", "E1", "E2", "L1", "D1", "W1"]
    assert distance == {"S1": 0, "E1": 1, "E2": 1, "L1": 2, "D1": 2, "W1": 3}


def test_dfs_follows_chains_first():
    steps = []
    order = _sample_graph().dfs("S1", steps=steps)
    assert order == ["S1", "E1", "L1", "W1", "E2", "D1"]
    assert any("Backtrack" in s for s in steps)
    assert "X" not in order


def test_find_path_explains_connection():
    hops = _sample_graph().find_path("W1", "D1")
    assert [(a, b) for a, b, _ in hops] == [("W1", "L1"), ("L1", "E1"), ("E1", "S1"), ("S1", "E2"), ("E2", "D1")]
    assert _sample_graph().find_path("S1", "X") is None
    assert _sample_graph().edge_count() == 5


def test_merge_sort_matches_python_sort_and_is_stable():
    rng = random.Random(42)
    data = [rng.randint(0, 50) for _ in range(300)]
    assert merge_sort(data) == sorted(data)
    assert merge_sort(data, reverse=True) == sorted(data, reverse=True)
    events = [{"t": "2026-03-13 22:00", "n": 1}, {"t": "2026-03-13 21:00", "n": 2}, {"t": "2026-03-13 22:00", "n": 3}]
    assert [e["n"] for e in merge_sort(events, key=lambda e: e["t"])] == [2, 1, 3]
    assert merge_sort([]) == [] and merge_sort([5]) == [5]


def test_binary_search():
    numbers = [f"CASE-{i:03d}" for i in range(1, 51)]
    steps = []
    assert binary_search(numbers, "CASE-037", steps=steps) == 36
    assert len(steps) <= 6                    # log2(50) is about 5.6
    assert binary_search(numbers, "CASE-099") == -1
    assert binary_search([], "x") == -1


def test_linear_and_keyword_search():
    records = [{"name": "Kamran Sheikh", "notes": "head librarian"}, {"name": "Sana Iqbal", "notes": "assistant"}]
    assert linear_search(records, lambda r: "librarian" in r["notes"]) == [records[0]]
    scored = keyword_search(records, "kamran librarian", ["name", "notes"], {"name": 3})
    assert scored == [(4, records[0])]
    assert keyword_search(records, "", ["name"]) == []
