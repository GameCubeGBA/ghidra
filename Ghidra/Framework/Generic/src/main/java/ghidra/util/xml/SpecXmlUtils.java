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
package ghidra.util.xml;

import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Utilities for encoding and decoding XML datatypes for use in specification files that
 * are validated by RelaxNG.  This currently includes the SLEIGH/Decompiler configuration files.
 * I.e.
 * 		.ldef files
 * 		.pspec files
 * 		.cspec files
 * 		.sla files
 *  
 *  Philosophy here is to use and enforce datatype encodings from XML schemas
 *  to try to be as standard as possible and facilitate use of relax grammars etc.  But in decoding
 *  possibly be a little more open to deal with resources generated outside of our control.
 *  
 * 
 *
 */
public class SpecXmlUtils {

	public static boolean decodeBoolean(String val) {
		if (val!=null && !val.isEmpty()) {
			switch(val.charAt(0)) {
			case 'y':
			case 't':
			case '1':
				return true;
			case 'n':
			case 'f':
			case '0':
				return false;
			default:
			}
		}
		return false;		// Should we throw an exception for bad encodings?
	}
	
	public static String encodeBoolean(boolean val) {
		return val ? "true" : "false";
	}
	
	public static void encodeBooleanAttribute(StringBuilder buf, String nm, boolean val) {
		buf.append(' ');
		buf.append(nm);
		buf.append("=\"");
		buf.append(val ? "true" : "false");
		buf.append('\"');
	}
	
	public static void encodeStringAttribute(StringBuilder buf, String nm, String val) {
		buf.append(' ');
		buf.append(nm);
		buf.append("=\"");
		buf.append(val);
		buf.append('\"');
	}
	
	public static String encodeSignedInteger(long val) {
		return Long.toString(val,10);
	}
	
	public static String encodeUnsignedInteger(long val) {
		return "0x" + Long.toHexString(val);
	}
	
	public static void encodeSignedIntegerAttribute(StringBuilder buf, String nm, long val) {
		buf.append(' ');
		buf.append(nm);
		buf.append("=\"");
		buf.append(encodeSignedInteger(val));
		buf.append('\"');
	}
	
	public static void encodeUnsignedIntegerAttribute(StringBuilder buf, String nm, long val) {
		buf.append(' ');
		buf.append(nm);
		buf.append("=\"");
		buf.append(encodeUnsignedInteger(val));
		buf.append('\"');
	}
	
	public static void encodeDoubleAttribute(StringBuilder buf, String nm, double val) {
		buf.append(' ');
		buf.append(nm);
		buf.append("=\"");
		buf.append(Double.toString(val));
		buf.append('\"');
	}
	
	public static int decodeInt(String intString ) {
	    // special case
	    if ( (intString == null) || "0".equals( intString ) ) {
	    	return 0;
	    }
	    
	    BigInteger bi = null;
	    if ( intString.startsWith( "0x" ) ) {
	        bi = new BigInteger( intString.substring( 2 ), 16 );
	    }
	    else if ( intString.startsWith( "0" ) ) {
	        bi = new BigInteger( intString.substring( 1 ), 8 );
	    }
	    else {
	        bi = new BigInteger( intString, 10 );
	    }
	    
	    return bi.intValue();
	}
	
	public static long decodeLong(String longString ) {
		// special case
	    if ( (longString == null) || "0".equals( longString ) ) {
	    	return 0;
	    }
	    
	    BigInteger bi = null;
	    if ( longString.startsWith( "0x" ) ) {
	        bi = new BigInteger( longString.substring( 2 ), 16 );
	    }
	    else if ( longString.startsWith( "0" ) ) {
	        bi = new BigInteger( longString.substring( 1 ), 8 );
	    }
	    else {
	        bi = new BigInteger( longString, 10 );
	    }
	    
	    return bi.longValue();
	}
	
	public static void xmlEscape(StringBuilder buf, String val) {
		for(int i=0;i<val.length();++i) {
			char c = val.charAt(i);
			// The check for escape characters needs to be efficient
			if (c <= '>') {		// Check against '>' first as most characters will fail immediately
				switch (c) {
					case '&':
						buf.append("&amp;");
						break;
					case '<':
						buf.append("&lt;");
						break;
					case '>':
						buf.append("&gt;");
						break;
					case '"':
						buf.append("&quot;");
						break;
					case '\'':
						buf.append("&apos;");
						break;
					default:
						buf.append(c);
				}
			}
			else
				buf.append(c);
		}
	}
	
	public static void xmlEscapeAttribute(StringBuilder buf, String nm, String val) {
		buf.append(' ');
		buf.append(nm);
		buf.append("=\"");
		xmlEscape(buf,val);
		buf.append('\"');
	}
		
	public static void xmlEscapeWriter(Writer writer, String val) throws IOException {
		for(int i=0;i<val.length();++i) {
			char c = val.charAt(i);
			switch (c) {
			case '&':
				writer.append("&amp;");
				break;
			case '<':
				writer.append("&lt;");
				break;
			case '>':
				writer.append("&gt;");
				break;
			case '"':
				writer.append("&quot;");
				break;
			case '\'':
				writer.append("&apos;");
				break;
			default:
				writer.append(c);
				break;
			}
		}
		
	}
	
	public static ErrorHandler getXmlHandler() {
		return new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw new SAXException("Error: "+exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw new SAXException("Fatal error: "+exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				throw new SAXException("Warning: "+exception);
			}
		};
	}
}
