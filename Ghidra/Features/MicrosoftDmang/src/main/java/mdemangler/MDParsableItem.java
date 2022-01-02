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
package mdemangler;

/**
 * This class is the base class of all parsable items of this demangler.
 */
public abstract class MDParsableItem {

	protected MDMang dmang;

	/**
	 * Constructor for this item (this class) that can be parsed by <b>{@code MDMang}</b>.
	 *  The <b>{@code MDMang}</b> argument is the worker for the demangler, which is used
	 *  throughout the parsing and outputting of the object.
	 * @param dmang the <b>{@code MDMang}</b> object (or derived type) for this MDParsableItem.
	 */
	public MDParsableItem(MDMang dmang) {
		this.dmang = dmang;
	}

	/**
	 * This is method can set the required <b>{@code dmang}</b> reference in this
	 *  class.  The normal way of setting this is through the constructor, which takes
	 *  the appropriate argument.  But if this class is constructed with
	 *  <b>{@code newInstance()}</b>, then we need a way to set the value.
	 * @param dmang the <b>{@code MDMang}</b> (or derived) worker for this
	 *  <b>{@code MDParsableItem}</b>.
	 */
	public void setMDMang(MDMang dmang) {
		this.dmang = dmang;
	}

	private int startIndexOffset = 0;

	public int getStartIndexOffset() {
		return startIndexOffset;
	}

	/**
	 * Constructor for this item (this class) that can be parsed by <b>{@code MDMang}</b>.
	 *  The <b>{@code MDMang}</b> argument is the worker for the demangler, which is used
	 *  throughout the parsing and outputting of the object.  The
	 *  <b>{@code startIndexOffset}</b> is indicates how many characters have already
	 *  been read from the mangled string at this point from the start of the sequence of
	 *  characters that led us to know that we had the object of this type.
	 *   <p>
	 *  This <b>{@code startIndexOffset}</b> value is used in the
	 *   <b>{@code MDMangParseInfo}</b> derivative of <b><code>MDMang</code></b>.
	 * @param dmang the <b>{@code MDMang}</b> (or derived) worker for this
	 *  <b>{@code MDParsableItem}</b>.
	 * @param startIndexOffset the offset from the start of the determining sequence.
	 */
	public MDParsableItem(MDMang dmang, int startIndexOffset) {
		this.dmang = dmang;
		this.startIndexOffset = startIndexOffset;
	}

	/******************************************************************************/
	/******************************************************************************/
	/**
	 * This method is here so that it can be overridden with extra processing code before and
	 *  after the call-back to any particular parser.
	 * @throws MDException On parsing error.
	 */
	public void parse() throws MDException {
		dmang.parseInfoPush(startIndexOffset, getClass().getSimpleName());
		parseInternal();
		dmang.parseInfoPop();
	}

	// Derived classes have contents. Base contents could be added here.
	protected abstract void parseInternal() throws MDException;

	// TODO: Consider abstract 
	public void insert(StringBuilder builder) {
		// Derived classes have contents. Base contents could be added here.
	}

	// TODO: Consider abstract 
	public void append(StringBuilder builder) {
		// Derived classes have contents. Base contents could be added here.
	}

	@Override
	public final String toString() {
		StringBuilder builder = new StringBuilder();
		insert(builder);
		// Following to to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
		dmang.cleanOutput(builder);
		return builder.toString();
	}
}
