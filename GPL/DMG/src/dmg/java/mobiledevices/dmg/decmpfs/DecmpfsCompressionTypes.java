/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.decmpfs;

public final class DecmpfsCompressionTypes {

	/** Uncompressed data in xattr. */
    public static final int CMP_Type1   = 1;

	/** Data stored in-line. */
    public static final int CMP_Type3   = 3;

	/** Resource fork contains compressed data. */
    public static final int CMP_Type4   = 4;

	/** ???? */
    public static final int CMP_Type10  = 10;

	public static final int CMP_MAX     = 255;

}
