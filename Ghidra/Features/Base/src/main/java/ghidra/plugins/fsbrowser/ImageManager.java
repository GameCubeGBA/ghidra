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
package ghidra.plugins.fsbrowser;

import javax.swing.ImageIcon;

import resources.Icons;
import resources.ResourceManager;

/**
 * Static helper to register and load Icons for the file system browser plugin and its
 * child windows.
 * <p>
 * Visible to just this package.
 */
public class ImageManager {
	//@formatter:off
    public static final ImageIcon COPY = ResourceManager.loadImage("images/page_copy.png");
	public static final ImageIcon CUT = ResourceManager.loadImage("images/edit-cut.png");
	public static final ImageIcon DELETE = ResourceManager.loadImage("images/page_delete.png");
	public static final ImageIcon FONT = ResourceManager.loadImage("images/text_lowercase.png");
	public static final ImageIcon LOCKED = ResourceManager.loadImage("images/lock.gif");
	public static final ImageIcon NEW = ResourceManager.loadImage("images/page_add.png");
	public static final ImageIcon PASTE = ResourceManager.loadImage("images/page_paste.png");
	public static final ImageIcon REDO = ResourceManager.loadImage("images/redo.png");
	public static final ImageIcon RENAME = ResourceManager.loadImage("images/textfield_rename.png");
	public static final ImageIcon REFRESH = Icons.REFRESH_ICON;
	public static final ImageIcon SAVE = ResourceManager.loadImage("images/disk.png");
	public static final ImageIcon SAVE_AS = ResourceManager.loadImage("images/disk_save_as.png");
	public static final ImageIcon UNDO = ResourceManager.loadImage("images/undo.png");
	public static final ImageIcon UNLOCKED = ResourceManager.loadImage("images/unlock.gif");
	public static final ImageIcon CLOSE = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/door.png");
	public static final ImageIcon COLLAPSE_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/arrow_in.png");
	public static final ImageIcon COMPRESS = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/compress.png");
	public static final ImageIcon CREATE_FIRMWARE = ResourceManager.loadImage("images/media-flash.png");
	public static final ImageIcon EXPAND_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/arrow_inout.png");
	public static final ImageIcon EXTRACT = ResourceManager.loadImage("images/package_green.png");
	public static final ImageIcon INFO = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/information.png");
	public static final ImageIcon OPEN = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/door_open.png");
	public static final ImageIcon OPEN_AS_BINARY = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/controller.png");
	public static final ImageIcon OPEN_IN_LISTING = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/folder_table.png");
	public static final ImageIcon OPEN_FILE_SYSTEM = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/folder_brick.png");
	public static final ImageIcon PHOTO = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/photo.png");
	public static final ImageIcon VIEW_AS_IMAGE = ResourceManager.loadImage("images/oxygen/16x16/games-config-background.png");
	public static final ImageIcon VIEW_AS_TEXT = ResourceManager.loadImage("images/format-text-bold.png");
	public static final ImageIcon UNKNOWN = ResourceManager.loadImage("images/help-browser.png");
	public static final ImageIcon IPOD = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/ipod.png");
	public static final ImageIcon IPOD_48 = ResourceManager.loadImage("images/oxygen/48x48/multimedia-player-apple-ipod.png");
	public static final ImageIcon ECLIPSE = ResourceManager.loadImage("images/eclipse.png");
	public static final ImageIcon JAR = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/page_white_cup.png");
	public static final ImageIcon KEY = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_key.png");
	public static final ImageIcon IMPORT = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_get.png");
	public static final ImageIcon iOS = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/phone.png");
	public static final ImageIcon OPEN_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_cascade.png");
	public static final ImageIcon LIST_MOUNTED = ResourceManager.loadImage("images/downArrow.png");
	//@formatter:on
}
