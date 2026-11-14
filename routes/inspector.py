from flask import Blueprint, render_template, request

from database.db import placeholders, query_all
from database.queries import (build_case_graph, build_evidence_index, evidence_for_cases, get_case_by_number,
                              list_cases)
from dsa.queue import Queue
from dsa.searching import binary_search, linear_search
from dsa.sorting import merge_sort
from dsa.stack import Stack
from dsa.tree import build_evidence_tree
from forensics.custody import load_custody_chain
from forensics.timeline import build_case_timeline
from routes.auth import accessible_case_ids, current_user, login_required

bp = Blueprint("inspector", __name__, url_prefix="/dsa")

ALGORITHMS = {
    "linked_list": ("Linked List - chain of custody", "dsa/linked_list.py", "append O(1), traverse/search O(n)"),
    "stack": ("Stack - note undo history", "dsa/stack.py", "push/pop O(1)"),
    "queue": ("Queue - evidence analysis tasks", "dsa/queue.py", "enqueue/dequeue O(1)"),
    "hash_table": ("Hash Table - evidence index", "dsa/hash_table.py", "average put/get O(1), worst O(n)"),
    "tree": ("Tree - case / folder / evidence hierarchy", "dsa/tree.py", "recursive traversal O(n)"),
    "bfs": ("Graph BFS - relationship exploration", "dsa/graph.py", "O(V + E)"),
    "dfs": ("Graph DFS - relationship exploration", "dsa/graph.py", "O(V + E)"),
    "merge_sort": ("Merge Sort - timeline ordering", "dsa/sorting.py", "O(n log n), stable"),
    "binary_search": ("Binary Search - case number lookup", "dsa/searching.py", "O(log n) on sorted data"),
    "linear_search": ("Linear Search - evidence keyword scan", "dsa/searching.py", "O(n)"),
}


@bp.route("/")
@login_required
def page():
    user = current_user()
    allowed = accessible_case_ids(user)
    cases = list_cases(allowed)
    algo = request.args.get("algo", "")
    case_number = request.args.get("case") or (cases[0]["case_number"] if cases else "")
    case = get_case_by_number(case_number)
    if case is None or case["id"] not in allowed:
        case = None

    evidence = evidence_for_cases(allowed)
    notes = []
    if allowed:
        notes = query_all("SELECT n.id, n.title, c.case_number, (SELECT COUNT(*) FROM note_history h "
                          "WHERE h.note_id = n.id) AS versions FROM investigation_notes n "
                          f"JOIN cases c ON c.id = n.case_id WHERE n.case_id IN ({placeholders(allowed)}) "
                          "ORDER BY versions DESC, n.id", tuple(allowed))

    run = None
    if algo in ALGORITHMS:
        runner = RUNNERS[algo]
        run = runner(request.args, allowed=allowed, case=case, evidence=evidence, cases=cases)
        title, source, complexity = ALGORITHMS[algo]
        run.update({"title": title, "source": source, "complexity": complexity})
    graph_nodes = build_case_graph(case["id"]).to_json()["nodes"] if case and algo in ("bfs", "dfs") else []
    return render_template("dsa.html", algorithms=ALGORITHMS, algo=algo, run=run, cases=cases, case=case,
                           evidence=evidence, notes=notes, graph_nodes=graph_nodes, args=request.args)


def _result(input_data, operation, result, steps=None, extra=None):
    return {"input": input_data, "operation": operation, "result": result, "steps": steps or [],
            "extra": extra}


def run_linked_list(args, evidence, **_):
    if not evidence:
        return _result([], "No evidence available.", [])
    evidence_id = args.get("evidence_id", type=int) or evidence[0]["id"]
    item = next((e for e in evidence if e["id"] == evidence_id), evidence[0])
    chain = load_custody_chain(item["id"])
    wanted = args.get("search", "verified")
    steps = []
    position = -1
    for index, event in enumerate(chain.traverse()):
        hit = wanted.lower() in event["action"].lower()
        steps.append(f"node {index}: '{event['action']}' -> {'MATCH' if hit else 'next'}")
        if hit:
            position = index
            break
    return _result(
        [f"{e['timestamp']}  {e['action']}  ({e['user_name'] or 'system'})" for e in chain],
        f"Load {len(chain)} custody events for {item['evidence_code']} into a LinkedList, traverse it, "
        f"then linearly search for the first action containing '{wanted}'.",
        [chain.display(lambda e: e["action"]),
         f"First match at position {position}" if position >= 0 else "No matching event"],
        steps, {"evidence_id": item["id"], "search": wanted})


def run_stack(args, allowed, **_):
    note_id = args.get("note_id", type=int)
    if not allowed:
        return _result([], "No accessible notes.", [])
    rows = query_all("SELECT h.*, n.case_id FROM note_history h JOIN investigation_notes n ON n.id = h.note_id "
                     f"WHERE h.note_id = ? AND n.case_id IN ({placeholders(allowed)}) ORDER BY h.id",
                     (note_id, *allowed)) if note_id else []
    stack = Stack()
    steps = []
    for row in rows:
        stack.push(row)
        steps.append(f"push version saved {row['saved_at']} -> stack size {len(stack)}")
    snapshot = [f"{r['saved_at']}: {r['content'][:70]}" for r in stack.to_list()]
    if stack.is_empty():
        return _result([], "This note has no saved previous versions (edit it once to create one).",
                       ["Stack is empty - Undo has nothing to restore."], steps, {"note_id": note_id})
    top = stack.pop()
    steps.append(f"pop -> {top['saved_at']} (this is what Undo would restore)")
    return _result([f"{r['saved_at']}: {r['content'][:70]}" for r in rows],
                   "Push every saved version (oldest first), then pop once. LIFO: the newest version comes off first.",
                   ["Stack top -> bottom before pop:"] + snapshot + [f"Popped: version saved {top['saved_at']}"],
                   steps, {"note_id": note_id})


def run_queue(args, case, **_):
    if case is None:
        return _result([], "Choose a case.", [])
    rows = query_all("SELECT t.*, e.evidence_code FROM analysis_tasks t JOIN evidence e ON e.id = t.evidence_id "
                     "WHERE t.case_id = ? AND t.status = 'pending' ORDER BY t.id", (case["id"],))
    queue = Queue()
    steps = []
    for row in rows:
        queue.enqueue(row)
        steps.append(f"enqueue task #{row['id']} ({row['task_type']} {row['evidence_code']}) -> size {len(queue)}")
    order = []
    while not queue.is_empty():          # drained in memory only; database is unchanged
        task = queue.dequeue()
        order.append(f"#{task['id']} {task['task_type']} {task['evidence_code']}")
        steps.append(f"dequeue #{task['id']}")
    return _result([f"#{r['id']} {r['task_type']} {r['evidence_code']} (requested {r['created_at']})" for r in rows],
                   f"Enqueue the pending tasks of {case['case_number']} and show the FIFO processing order "
                   "(simulation; queue tasks from the Forensic Tools tab).",
                   order or ["No pending tasks. Queue some from the case's Forensic Tools tab."], steps)


def run_hash_table(args, evidence, **_):
    table = build_evidence_index(evidence)
    key = (args.get("key") or (evidence[-1]["evidence_code"] if evidence else "EV-0001")).strip().upper()
    value, bucket, comparisons = table.get_with_trace(key)
    buckets = [f"bucket {i:>2}: {', '.join(keys) if keys else '-'}" for i, keys in table.bucket_report()]
    return _result(
        [f"{e['evidence_code']} -> {e['filename']}" for e in evidence],
        f"put() every evidence record keyed by evidence ID, then get('{key}').",
        [f"Found {value['evidence_code']}: {value['filename']} ({value['case_number']})" if value else "Key not found",
         f"Hash -> bucket {bucket}, {comparisons} key comparison(s) in that bucket",
         f"Capacity {table.capacity}, {len(table)} keys, load factor {len(table) / table.capacity:.2f}, "
         f"{table.collisions} collision(s), {table.resizes} resize(s)"],
        buckets, {"key": key})


def run_tree(args, cases, evidence, **_):
    root = build_evidence_tree(cases, evidence)
    order = root.preorder()
    return _result(
        [f"{c['case_number']} {c['title']}" for c in cases],
        "Build root -> case -> type folder -> evidence, then run a recursive pre-order traversal.",
        [root.render(), f"Nodes: {root.count()}   Height: {root.height()}"],
        [f"{'  ' * depth}visit [{node.kind}] {node.name}" for depth, node in order])


def _run_traversal(args, case, kind):
    if case is None:
        return _result([], "Choose a case.", [])
    graph = build_case_graph(case["id"])
    nodes = list(graph.adjacency)
    if not nodes:
        return _result([], "This case has no graph nodes yet.", [])
    start = args.get("start") if args.get("start") in graph.adjacency else nodes[0]
    steps = []
    if kind == "bfs":
        order, distance = graph.bfs(start, steps=steps)
        result = [f"{i + 1}. {graph.label(n)} (level {distance[n]})" for i, n in enumerate(order)]
    else:
        order = graph.dfs(start, steps=steps)
        result = [f"{i + 1}. {graph.label(n)}" for i, n in enumerate(order)]
    unreached = [graph.label(n) for n in nodes if n not in order]
    if unreached:
        result.append("Not reachable from start: " + ", ".join(unreached))
    adjacency = [f"{graph.label(n)} -> " + (", ".join(graph.label(m) for m, _ in graph.neighbors(n)) or "-")
                 for n in nodes]
    return _result(adjacency, f"{kind.upper()} from '{graph.label(start)}' over {graph.node_count()} nodes and "
                              f"{graph.edge_count()} recorded relationships (adjacency list shown as input).",
                   result, steps, {"start": start})


def run_merge_sort(args, case, **_):
    if case is None:
        return _result([], "Choose a case.", [])
    # The unsorted input, in the order it was collected from the different tables.
    unsorted = build_case_timeline(case["id"], include_system=True, sort=False)
    steps = []
    ordered = merge_sort(unsorted, key=lambda e: e["time"], steps=steps)
    return _result([f"{e['time']}  {e['type']}" for e in unsorted],
                   f"Merge sort {len(unsorted)} timeline events of {case['case_number']} by timestamp.",
                   [f"{e['time']}  {e['type']}" for e in ordered], steps)


def run_binary_search(args, cases, **_):
    target = (args.get("target") or (cases[-1]["case_number"] if cases else "CASE-001")).strip().upper()
    ordered = merge_sort([dict(c) for c in cases], key=lambda c: c["case_number"])
    steps = []
    index = binary_search(ordered, target, key=lambda c: c["case_number"], steps=steps)
    return _result([c["case_number"] for c in ordered],
                   f"Binary search for '{target}' in the sorted list of case numbers.",
                   [f"Found at index {index}: {ordered[index]['title']}" if index >= 0 else "Not found"],
                   steps, {"target": target})


def run_linear_search(args, evidence, **_):
    word = (args.get("word") or "log").strip().lower()
    steps = []
    matches = linear_search([dict(e) for e in evidence],
                            lambda e: word in f"{e['filename']} {e['description']}".lower(), steps=steps)
    steps = [f"{s}  ({evidence[i]['evidence_code']})" for i, s in enumerate(steps)]
    return _result([f"{e['evidence_code']} {e['filename']}" for e in evidence],
                   f"Linear search: check every evidence record for '{word}' in its name or description.",
                   [f"{m['evidence_code']} {m['filename']}" for m in matches] or ["No matches"],
                   steps, {"word": word})


RUNNERS = {
    "linked_list": run_linked_list,
    "stack": run_stack,
    "queue": run_queue,
    "hash_table": run_hash_table,
    "tree": run_tree,
    "bfs": lambda args, case, **kw: _run_traversal(args, case, "bfs"),
    "dfs": lambda args, case, **kw: _run_traversal(args, case, "dfs"),
    "merge_sort": run_merge_sort,
    "binary_search": run_binary_search,
    "linear_search": run_linear_search,
}
