/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

/**
 * Represents kinds of BTNodeDescriptor.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html">hfs/hfs_format.h</a>
 * @see <a href="https://developer.apple.com/library/archive/technotes/tn/tn1150.html">B-Trees</a> 
 */
public final class BTreeNodeKinds {

	public static final byte kBTLeafNode = -1;
	public static final byte kBTIndexNode = 0;
	public static final byte kBTHeaderNode = 1;
	public static final byte kBTMapNode = 2;

}
