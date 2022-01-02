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
package docking.widgets.tree.support;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.tree.TreePath;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeLazyNode;
import docking.widgets.tree.GTreeNode;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class NewTestApp extends JPanel {
	private static final long serialVersionUID = 1L;

	public NewTestApp() {
	}

	public static void main(String[] args) {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		}
		catch (Exception e1) {
		}
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, Boolean.FALSE.toString());
		JFrame frame = new JFrame("Test App");
		frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		Container container = frame.getContentPane();
		container.setLayout(new BorderLayout());
		final RootNode root = new RootNode(new File("C:\\clear_svn\\Ghidra_trunk\\Ghidra"));
		final GTree tree = new GTree(root);
		tree.setDragNDropHandler(new DragNDropHandler());
		container.add(tree, BorderLayout.CENTER);
		JButton button = new JButton("Push Me");
		container.add(button, BorderLayout.PAGE_END);
		frame.setSize(400, 600);
		frame.setVisible(true);
		button.addActionListener(e -> {
			TreePath selectionPath = tree.getSelectionPath();
			if (selectionPath != null) {
				GTreeNode node = (GTreeNode) selectionPath.getLastPathComponent();
				tree.collapseAll(node);
			}
		});

	}

	public static long getMemoryUsage() {
		Runtime rt = Runtime.getRuntime();
		return rt.totalMemory() - rt.freeMemory();
	}
}

@FunctionalInterface
interface FileData {
	File getFile();
}

class FileNode extends GTreeNode implements FileData {
	protected File file;
	public String tempName;

	FileNode(File file) {
		this.file = file;
	}

	@Override
	public File getFile() {
		return file;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getName() {
		if (tempName != null) {
			return tempName;
		}
		String name = file.getName();
		if (!name.isEmpty()) {
			return name;
		}
		return file.getName();
	}

	@Override
	public String getToolTip() {
		return file.getAbsolutePath();
	}

	@Override
	public int compareTo(GTreeNode o) {
		if (o instanceof DirectoryNode) {
			return 1;
		}
		return getName().compareTo(o.getName());
	}

	@Override
	public String toString() {
		return file.getAbsolutePath();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof FileNode) {
			return file.equals(((FileNode) obj).file);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return file.getAbsolutePath().hashCode();
	}

	@Override
	public boolean isLeaf() {
		return true;
	}
}

class DirectoryNode extends GTreeLazyNode implements FileData {
	private final File file;

	DirectoryNode(File file) {
		this.file = file;

	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public File getFile() {
		return file;
	}

	@Override
	public List<GTreeNode> generateChildren() {
		List<GTreeNode> children = new ArrayList<>();
		File[] files = file.listFiles();
		if (files != null) {
			for (File directoryFile : files) {
				if (directoryFile.isDirectory()) {
					children.add(new DirectoryNode(directoryFile));
				}
				else {
					children.add(new FileNode(directoryFile));
				}
			}
		}
		Collections.sort(children);
		return children;
	}

	@Override
	public int compareTo(GTreeNode o) {
		if (!(o instanceof DirectoryNode)) {
			return -1;
		}
		return getName().compareTo(o.getName());
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public String getToolTip() {
		return file.getAbsolutePath();
	}

	@Override
	public int hashCode() {
		return file.getAbsolutePath().hashCode();
	}

}

class RootNode extends DirectoryNode {
	RootNode(File file) {
		super(file);
	}
}

class DragNDropHandler implements GTreeDragNDropHandler {
	public static DataFlavor[] supportedFlavors = {
		DataFlavor.stringFlavor,
		DataFlavor.javaFileListFlavor
	};

	@Override
	public void drop(GTreeNode destUserData, Transferable transferable, int dropAction) {
		Msg.info(this, "Dropped the following Files onto " + destUserData);
		try {
			List<?> list = (List<?>) transferable.getTransferData(DataFlavor.javaFileListFlavor);
            for (Object o : list) {
                Msg.info(this, "\t" + o);
            }
		}
		catch (UnsupportedFlavorException | IOException e) {
		}
	}

	@Override
	public DataFlavor[] getSupportedDataFlavors(List<GTreeNode> dragUserData) {
		return supportedFlavors;
	}

	@Override
	public int getSupportedDragActions() {
		return DnDConstants.ACTION_COPY;
	}

	@Override
	public Object getTransferData(List<GTreeNode> dragUserData, DataFlavor flavor) {
		if (flavor.equals(DataFlavor.javaFileListFlavor)) {
			List<File> fileList = new ArrayList<>();
			for (GTreeNode node : dragUserData) {
				FileData fileData = (FileData) node;
				fileList.add(fileData.getFile());
			}
			return fileList;
		}
		else if (flavor.equals(DataFlavor.stringFlavor)) {
			StringBuilder buf = new StringBuilder();
            for (GTreeNode dragUserDatum : dragUserData) {
                buf.append(dragUserDatum.toString());
                buf.append("\n");
            }
			return buf.toString();
		}
		return null;

	}

	@Override
	public boolean isDropSiteOk(GTreeNode destUserData, DataFlavor[] flavors, int dropAction) {
		if (containsFlavor(flavors, DataFlavor.javaFileListFlavor)) {
			return (destUserData instanceof DirectoryNode);
		}
		return false;
	}

	private boolean containsFlavor(DataFlavor[] flavors, DataFlavor flavor) {
		for (DataFlavor flavor2 : flavors) {
			if (flavor2.equals(flavor)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean isStartDragOk(List<GTreeNode> dragUserData, int dragAction) {
		return true;
	}
}
