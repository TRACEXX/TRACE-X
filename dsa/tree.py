FOLDER_NAMES = {
    "image": "Images",
    "video": "CCTV / Video",
    "audio": "Audio Recordings",
    "pdf": "PDF Documents",
    "text": "Text Documents",
    "csv": "CSV Activity Logs",
    "other": "Other Files",
}


class TreeNode:
    def __init__(self, name, kind, ref=None):
        self.name = name        # text shown to the user
        self.kind = kind        # 'root', 'case', 'folder' or 'evidence'
        self.ref = ref          # e.g. case number or evidence id
        self.children = []

    def add_child(self, node):
        self.children.append(node)
        return node

    def find(self, predicate):
        """Recursive depth-first search for the first node matching predicate."""
        if predicate(self):
            return self
        for child in self.children:
            found = child.find(predicate)
            if found is not None:
                return found
        return None

    def count(self):
        """Total number of nodes in this subtree (recursive)."""
        return 1 + sum(child.count() for child in self.children)

    def height(self):
        """Number of levels below this node (a leaf has height 0)."""
        if not self.children:
            return 0
        return 1 + max(child.height() for child in self.children)

    def preorder(self, depth=0, result=None):
        """Recursive pre-order traversal: visit node, then its children.

        Returns a list of (depth, node) pairs.
        """
        if result is None:
            result = []
        result.append((depth, self))
        for child in self.children:
            child.preorder(depth + 1, result)
        return result

    def to_dict(self):
        """Convert the subtree into nested dictionaries (recursive)."""
        return {
            "name": self.name,
            "kind": self.kind,
            "ref": self.ref,
            "children": [child.to_dict() for child in self.children],
        }

    def render(self, prefix=""):
        """Plain-text drawing of the tree, like the `tree` command."""
        lines = [self.name]
        for i, child in enumerate(self.children):
            last = i == len(self.children) - 1
            child_lines = child.render().split("\n")
            lines.append(("└── " if last else "├── ") + child_lines[0])
            for extra in child_lines[1:]:
                lines.append(("    " if last else "│   ") + extra)
        return "\n".join(lines)


def build_evidence_tree(cases, evidence_rows):
    """Build root -> case -> type folder -> evidence from database rows.

    `cases` needs keys id, case_number, title.
    `evidence_rows` needs keys id, case_id, evidence_code, filename, file_type.
    """
    root = TreeNode("TRACE X Evidence Archive", "root")
    case_nodes = {}
    for case in cases:
        case_nodes[case["id"]] = root.add_child(
            TreeNode(f'{case["case_number"]}  {case["title"]}', "case", case["case_number"]))

    folders = {}
    for item in evidence_rows:
        case_node = case_nodes.get(item["case_id"])
        if case_node is None:
            continue
        folder_key = (item["case_id"], item["file_type"])
        if folder_key not in folders:
            folder_name = FOLDER_NAMES.get(item["file_type"], "Other Files")
            folders[folder_key] = case_node.add_child(TreeNode(folder_name, "folder"))
        folders[folder_key].add_child(
            TreeNode(f'{item["evidence_code"]}  {item["filename"]}', "evidence", item["id"]))
    return root
