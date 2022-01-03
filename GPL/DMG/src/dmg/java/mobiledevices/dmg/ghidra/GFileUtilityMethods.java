/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;

import java.io.*;


public final class GFileUtilityMethods {

	private static final String GHIDRA_FILE_SYSTEM_PREFIX = "ghidra_file_system_";
	private static final String GHIDRA_FILE_SYSTEM_SUFFIX = ".tmp";

	public static final File writeTemporaryFile(InputStream inputStream ) throws IOException {
		return writeTemporaryFile( inputStream , Integer.MAX_VALUE );
	}

	public static final File writeTemporaryFile(InputStream inputStream, int maxBytesToWrite ) throws IOException {
		File tempOutputFile = File.createTempFile( GHIDRA_FILE_SYSTEM_PREFIX, GHIDRA_FILE_SYSTEM_SUFFIX );
		tempOutputFile.deleteOnExit();
		OutputStream outputStream = new FileOutputStream( tempOutputFile );
		try {
			int nWritten = 0;
			byte [] buffer = new byte[ 8192 ];
			while ( true ) {
				int nRead = inputStream.read( buffer );
				if ( nRead == -1 ) {
					break;
				}
				outputStream.write( buffer, 0, nRead );
				nWritten += nRead;
				if ( nWritten >= maxBytesToWrite ) {
					break;
				}
			}
		}
		finally {
			outputStream.close();
		}
		return tempOutputFile;
	}

	public static final File writeTemporaryFile(byte [] bytes, String prefix ) throws IOException {
		if ( prefix == null ) {
			prefix = GHIDRA_FILE_SYSTEM_PREFIX;
		}
		if ( prefix.length() < 3 ) {//temp file prefix must be at least 3 chars in length
            StringBuilder prefixBuilder = new StringBuilder(prefix);
            for (int i = prefixBuilder.length(); i < 3 ; ++i ) {
				prefixBuilder.append('_');
			}
            prefix = prefixBuilder.toString();
        }
		File tempFile = File.createTempFile( prefix , GHIDRA_FILE_SYSTEM_SUFFIX );
		tempFile.deleteOnExit();
		OutputStream tempFileOut = new FileOutputStream( tempFile );
		try {
			tempFileOut.write( bytes );
		}
		finally {
			tempFileOut.close();
		}
		return tempFile;
	}
}
