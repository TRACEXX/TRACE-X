from dsa.queue import Queue


class Graph:
    def __init__(self):
        self.adjacency = {}     # node -> list of (neighbour, edge_info)
        self.labels = {}        # node -> human readable label
        self.types = {}         # node -> 'suspect', 'evidence', ...

    def add_node(self, node, label=None, node_type=None):
        if node not in self.adjacency:
            self.adjacency[node] = []
        if label:
            self.labels[node] = label
        if node_type:
            self.types[node] = node_type

    def add_edge(self, source, target, info=None):
        """Add an undirected edge. `info` holds type, description and id."""
        self.add_node(source)
        self.add_node(target)
        info = dict(info or {})
        info["recorded_from"] = source
        info["recorded_to"] = target
        self.adjacency[source].append((target, info))
        self.adjacency[target].append((source, info))

    def neighbors(self, node):
        return self.adjacency.get(node, [])

    def label(self, node):
        return self.labels.get(node, node)

    def node_count(self):
        return len(self.adjacency)

    def edge_count(self):
        return sum(len(edges) for edges in self.adjacency.values()) // 2

    # ------------------------------------------------------------------ BFS
    def bfs(self, start, steps=None):
        """Breadth-first search from `start`.

        Visits all nodes 1 link away, then 2 links away, and so on.
        Returns (visit order, {node: distance in links}).
        If a `steps` list is given, a description of each step is appended.
        """
        if start not in self.adjacency:
            return [], {}
        visited = {start}
        distance = {start: 0}
        order = []
        queue = Queue()
        queue.enqueue(start)
        while not queue.is_empty():
            node = queue.dequeue()
            order.append(node)
            if steps is not None:
                steps.append(f"Dequeue {self.label(node)} (level {distance[node]})")
            for neighbour, _ in self.neighbors(node):
                if neighbour not in visited:
                    visited.add(neighbour)
                    distance[neighbour] = distance[node] + 1
                    queue.enqueue(neighbour)
                    if steps is not None:
                        steps.append(f"  enqueue {self.label(neighbour)}")
        return order, distance

    # ------------------------------------------------------------------ DFS
    def dfs(self, start, steps=None):
        """Depth-first search from `start` (recursive).

        Follows one chain of links as deep as possible before backtracking.
        Returns the visit order.
        """
        if start not in self.adjacency:
            return []
        visited = set()
        order = []
        self._dfs_visit(start, visited, order, 0, steps)
        return order

    def _dfs_visit(self, node, visited, order, depth, steps):
        visited.add(node)
        order.append(node)
        if steps is not None:
            steps.append("  " * depth + f"Visit {self.label(node)}")
        for neighbour, _ in self.neighbors(node):
            if neighbour not in visited:
                self._dfs_visit(neighbour, visited, order, depth + 1, steps)
        if steps is not None and depth > 0:
            steps.append("  " * depth + f"Backtrack from {self.label(node)}")

    # -------------------------------------------------------- explanations
    def find_path(self, start, goal):
        if start not in self.adjacency or goal not in self.adjacency:
            return None
        if start == goal:
            return []
        parent = {start: None}
        queue = Queue()
        queue.enqueue(start)
        while not queue.is_empty():
            node = queue.dequeue()
            for neighbour, info in self.neighbors(node):
                if neighbour not in parent:
                    parent[neighbour] = (node, info)
                    if neighbour == goal:
                        return self._rebuild_path(parent, goal)
                    queue.enqueue(neighbour)
        return None

    @staticmethod
    def _rebuild_path(parent, goal):
        hops = []
        node = goal
        while parent[node] is not None:
            previous, info = parent[node]
            hops.append((previous, node, info))
            node = previous
        hops.reverse()
        return hops

    def to_json(self):
        nodes = [{"id": n, "label": self.label(n), "type": self.types.get(n, n.split(":")[0])}
                 for n in self.adjacency]
        seen = set()
        edges = []
        for node, links in self.adjacency.items():
            for _, info in links:
                if info.get("id") in seen:
                    continue
                seen.add(info.get("id"))
                edges.append({
                    "id": info.get("id"),
                    "source": info["recorded_from"],
                    "target": info["recorded_to"],
                    "type": info.get("type", ""),
                    "description": info.get("description", ""),
                })
        return {"nodes": nodes, "edges": edges}
