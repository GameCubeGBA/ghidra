/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.btree;

public final class BTreeTypes {

	/** Control file */
    public static final byte kHFSBTreeType       = 0;
	/** User bTree types start from 128 */
    public static final byte kUserBTreeType      =  (byte)128;
	/** */
    public static final byte kReservedBTreeType  =  (byte)255;
}
