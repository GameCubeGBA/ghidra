/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package generic.jar;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class ClassModuleTree {
	private FileNode root = new FileNode(null, "");

	public ClassModuleTree() {

	}

	public ClassModuleTree(ResourceFile treeFile) throws IOException {

		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(treeFile.getInputStream()))) {
			String line;
			while ((line = reader.readLine()) != null) {
				String[] split = line.split(" ");
				String path = split[0];
				String module = "null".equals(split[1]) ? null : split[1];
				addNode(path, module);
			}
		}
	}

	public void addNode(String path, String moduleName) {
		String[] split = path.split("/");
		FileNode file = root;
		for (String string : split) {
			file = file.createNode(string);
		}
		file.setModule(moduleName);
	}

	@Override
	public boolean equals(Object obj) {
		if ((obj == null) || (obj.getClass() != this.getClass())) {
			return false;
		}
		ClassModuleTree other = (ClassModuleTree) obj;
		return root.equals(other.root);
	}

	@Override
	public int hashCode() {
		return root.hashCode();
	}

	public void trim() {
		root.trim();
	}

	public void printRecursively() {
		printRecursively(root);
	}

	public void saveFile(File outputFile) throws IOException {
		try (FileWriter writer = new FileWriter(outputFile)) {
			List<FileNode> children = root.getChildren();
			for (FileNode child : children) {
				writeRecursively(writer, child);
			}
		}
	}

	private void writeRecursively(FileWriter writer, FileNode node) throws IOException {
		writer.write(node.getPath());
		writer.write(" ");
		writer.write(node.module == null ? "null" : node.module);
		writer.write("\n");
		List<FileNode> children = node.getChildren();
		for (FileNode child : children) {
			writeRecursively(writer, child);
		}
	}

	private void printRecursively(FileNode node) {
		System.out.println(node.getPath() + "  :   " + node.module);
		List<FileNode> children = node.getChildren();
		for (FileNode child : children) {
			printRecursively(child);
		}

	}

	public int getNodeCount() {
		return root.getCount();
	}

	static class FileNode implements Comparable<FileNode> {
		private FileNode parent;
		private Map<String, FileNode> children;
		private String module;
		private String name;

		public FileNode(FileNode parent, String name) {
			this.parent = parent;
			this.name = name;
		}

		public int getCount() {
			int count = 1;
			if (children != null) {
				List<FileNode> childList = getChildren();
				for (FileNode child : childList) {
					count += child.getCount();
				}
			}
			return count;
		}

		public String trim() {
			if (module != null) {
				return module;
			}
			if (children == null) {
				return null;
			}
			Set<String> set = new HashSet<>();
			for (FileNode node : children.values()) {
				set.add(node.trim());
			}
			if (set.size() == 1) {
				module = set.iterator().next();
				if (module != null) {
					children = null;  // trim the children
				}
			}
			return module;
		}

		@Override
		public int hashCode() {
			return Objects.hash(children, module, name);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if ((obj == null) || (getClass() != obj.getClass()))
				return false;
			FileNode other = (FileNode) obj;
			if (!Objects.equals(children, other.children)) {
				return false;
			}
			if (!Objects.equals(module, other.module)) {
				return false;
			}
			if (!Objects.equals(name, other.name)) {
				return false;
			}
			return true;
		}

		public void setModule(String moduleName) {
			this.module = moduleName;
		}

		public String getPath() {
			if (parent == null) {
				return "";
			}
			String parentPath = parent.getPath();
			if (parentPath.length() == 0) {
				return name;
			}
			return parentPath + "/" + name;
		}

		public FileNode createNode(String nodeName) {
			if (children == null) {
				children = new HashMap<>();
			}
			FileNode child = children.get(nodeName);
			if (child == null) {
				child = new FileNode(this, nodeName);
				children.put(nodeName, child);
			}
			return child;
		}

		public List<FileNode> getChildren() {
			if (children == null) {
				return new ArrayList<>();
			}
			return new ArrayList<>(children.values());
		}

		@Override
		public int compareTo(FileNode o) {
			return name.compareTo(o.name);
		}

		public FileNode getChild(String childName) {
			if (children == null) {
				return null;
			}
			return children.get(childName);
		}
	}

	public String getModuleName(String className) {
		String[] split = className.split("/");
		FileNode node = root;
		for (String name : split) {
			node = node.getChild(name);
			if (node == null) {
				return null;
			}
			if (node.module != null) {
				return node.module;
			}
		}
		return null;
	}

	public static void main(String[] args) {
		ClassModuleTree tree = new ClassModuleTree();
		tree.addNode("a/b/c", "module1");
		tree.addNode("a/b/d", "module1");
		tree.addNode("a/b/e", "module1");

		tree.addNode("a/x/a", "module2");
		tree.addNode("a/x/b", "module3");

		tree.printRecursively();
		System.out.println("------");
		tree.trim();
		tree.printRecursively();

	}

}
