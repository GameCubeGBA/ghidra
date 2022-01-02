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
package ghidra.javaclass.flags;

public enum MethodsInfoAccessFlags {
	/** Declared public; may be accessed from outside its package. */
	ACC_PUBLIC(0x0001),
	/** Declared private; accessible only within the defining class. */
	ACC_PRIVATE(0x0002),
	/** Declared protected; may be accessed within subclasses. */
	ACC_PROTECTED(0x0004),
	/** Declared static. */
	ACC_STATIC(0x0008),
	/** Declared final; must not be overridden (5.4.5). */
	ACC_FINAL(0x0010),
	/** Declared synchronized; invocation is wrapped by a monitor use. */
	ACC_SYNCHRONIZED(0x0020),
	/** A bridge method, generated by the compiler. */
	ACC_BRIDGE(0x0040),
	/** Declared with variable number of arguments. */
	ACC_VARARGS(0x0080),
	/** Declared native; implemented in a language other than Java. */
	ACC_NATIVE(0x0100),
	/** Declared abstract; no implementation is provided. */
	ACC_ABSTRACT(0x0400),
	/** Declared strictfp; floating-point mode is FP-strict. */
	ACC_STRICT(0x0800),
	/** Declared synthetic; not present in the source code. */
	ACC_SYNTHETIC(0x1000);

	private final int value;

	private MethodsInfoAccessFlags(int value) {
		this.value = value;
	}

	public int getValue() {
		return value;
	}

	/**
	 * Return a text representation for a given set of access flags.  
	 * Here are some examples:
	 * <DL>
	 *  <DD>{@code "public static final"},</DD>
	 *  <DD>{@code "package private"}, or</DD>
	 *  <DD>{@code "protected transient"}.</DD>
	 * </DL>
	 * Note: only access flags that map to Java modifier keywords are returned.
	 * @param access the mask of flags denoting access permission.
	 * @return a text representation of the access flags.
	 */
	public static String toString(int access) {
		StringBuffer stringBuffer = new StringBuffer();
		if ((access & ACC_PUBLIC.value) == ACC_PUBLIC.value) {
			stringBuffer.append("public ");
		}
		if ((access & ACC_PRIVATE.value) == ACC_PRIVATE.value) {
			stringBuffer.append("private ");
		}
		if ((access & ACC_PROTECTED.value) == ACC_PROTECTED.value) {
			stringBuffer.append("protected ");
		}
		if ((access & ACC_STATIC.value) == ACC_STATIC.value) {
			stringBuffer.append("static ");
		}
		if ((access & ACC_FINAL.value) == ACC_FINAL.value) {
			stringBuffer.append("final ");
		}
		if ((access & ACC_SYNCHRONIZED.value) == ACC_SYNCHRONIZED.value) {
			stringBuffer.append("synchronized ");
		}
		if ((access & ACC_NATIVE.value) == ACC_NATIVE.value) {
			stringBuffer.append("native ");
		}
		if ((access & ACC_ABSTRACT.value) == ACC_ABSTRACT.value) {
			stringBuffer.append("abstract ");
		}
		return stringBuffer.toString().trim();
	}

}
