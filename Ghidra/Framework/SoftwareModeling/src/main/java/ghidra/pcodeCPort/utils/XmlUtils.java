/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.utils;

import java.io.PrintStream;
import java.math.BigInteger;

public class XmlUtils {

	private XmlUtils() { 
		// utils class
	}
	
	public static void a_v( PrintStream s, String attr, String val ) {
		s.append( ' ' ).append( attr ).append( "=\"" );		
		xml_escape(s,val);
		s.append( "\"" );
	}

	public static void a_v_i( PrintStream s, String attr, long val) {
		s.append( ' ' ).append( attr ).append( "=\"" );
		s.append( Long.toString(val, 10) ).append( "\"" );
	}

	public static void a_v_u( PrintStream s, String attr, long val ) {
		s.append( ' ' ).append( attr ).append( "=\"0x" );
		s.append( Long.toHexString(val) ).append( "\"" );
	}

	public static void a_v_b( PrintStream s, String attr, boolean val ) {
		s.append( ' ' ).append( attr ).append( "=\"" );
		s.append( val ? "true" : "false" ).append( "\"" );
	}
	public static boolean decodeBoolean(String boolString) {
		if ((boolString == null)||(boolString.length()==0)) {
			return false;
		}
		char firstc = boolString.charAt(0);
		switch (firstc) {
		case 't':
			return true;
		case '1':
			return true;
		case 'y':
			return true;
		default:
			break;
		}
		return false;
	}

	public static int decodeUnknownInt( String intString ) {
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
	
	public static long decodeUnknownLong( String longString ) {
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
	
	// Escape xml tag indicators
	public static void xml_escape( PrintStream s, String str ) { 
		for ( int i = 0; i < str.length(); i++ ) {
			char c = str.charAt( i );
			switch (c) {
			case '<':
				s.append( "&lt;" );
				break;
			case '>':
				s.append( "&gt;" );
				break;
			case '"':
				s.append( "&quot;" );
				break;
			case '\'':
				s.append( "&apos;" );
				break;
			case '&':
				s.append( "&amp;" );
				break;
			default:
				s.append( c );
				break;
			}
		}
	}
}
