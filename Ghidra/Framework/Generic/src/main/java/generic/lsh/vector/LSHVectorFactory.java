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
package generic.lsh.vector;

import java.io.IOException;

import org.xml.sax.SAXException;

import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public abstract class LSHVectorFactory {
	protected WeightFactory weightFactory = null;	// Container for vector weighting information and score normalization
	protected IDFLookup idfLookup = null;			// Container for Inverse Document Frequency (IDF) information
	protected int settings;							// Settings used to generate weights and lookup hashes

	/**
	 * Generate vector with all coefficients zero.
	 * @return the zero vector
	 */
	public abstract LSHVector buildZeroVector();

	/**
	 * Generate an LSHVector from a feature set, individual features are integer hashes.
	 * The integers MUST already be sorted.
	 * The same integer can occur more than once in the array (term frequency (TF) &gt; 1).
	 * The factory decides internally how to create weights based on term frequency and any
	 * knowledge of Inverse Document Frequency (IDF)
	 * @param feature is the sorted array of integer features
	 * @return the newly minted LSHVector
	 */
	public abstract LSHVector buildVector(int[] feature);

	/**
	 * Generate an LSHVector based on XML tag seen by pull parser.
	 * Factory generates weights based on term frequency info in the XML tag and its internal IDF knowledge
	 * @param parser is the XML parser
	 * @return the newly minted LSHVector
	 */
	public abstract LSHVector restoreVectorFromXml(XmlPullParser parser);

	/**
	 * Generate an LSHVector based on string returned from SQL query
	 * Factory generates weights based on term frequency info in the string and its internal IDF knowledge
	 * @param sql is the column data string returned by an SQL query
	 * @return the newly minted LSHVector
	 * @throws IOException
	 */
	public abstract LSHVector restoreVectorFromSql(String sql) throws IOException;

	/**
	 * Load the factory with weights and the feature map
	 * @param wFactory is the weight table of IDF and TF weights
	 * @param iLookup is the map from features int the weight table
	 * @param settings is an integer id for this particular weighting scheme
	 */
	public void set(WeightFactory wFactory, IDFLookup iLookup, int settings) {
		weightFactory = wFactory;
		idfLookup = iLookup;
		this.settings = settings;
	}

	/**
	 * @return true if this factory has weights and lookup loaded
	 */
	public boolean isLoaded() {
		return ((idfLookup != null) && (!idfLookup.empty()));
	}

	/**
	 * @return the weighttable's significance scale for this factory
	 */
	public double getSignificanceScale() {
		return weightFactory.getScale();
	}

	/**
	 * @return the weighttable's significance addend for this factory
	 */
	public double getSignificanceAddend() {
		return weightFactory.getAddend();
	}

	/**
	 * @return settings ID used to generate factory's current weights
	 */
	public int getSettings() {
		return settings;
	}

	/**
	 * Calculate a vector's significance as compared to itself, normalized for this factory's specific weight settings
	 * @param vector is the LSHVector
	 * @return the vector's significance score
	 */
	public double getSelfSignificance(LSHVector vector) {
		return vector.getLength() * vector.getLength() + weightFactory.getAddend();
	}

	/**
	 * Given comparison data generated by the LSHVector.compare() method,
	 * calculate the significance of any similarity between the two vectors,
	 * normalized for this factory's specific weight settings
	 * @param data is the comparison object produced when comparing two LSHVectors
	 * @return the significance score
	 */
	public double calculateSignificance(VectorCompare data) {
		data.fillOut();
		return data.dotproduct -
			data.numflip *
				(weightFactory.getFlipNorm0() + weightFactory.getFlipNorm1() / data.max) -
			data.diff * (weightFactory.getDiffNorm0() + weightFactory.getDiffNorm1() / data.max) +
			weightFactory.getAddend();
	}

	/**
	 * Read both the weights and the lookup hashes from an XML stream
	 * @param parser is the XML parser
	 * @throws SAXException
	 */
	public void readWeights(XmlPullParser parser) throws SAXException {
		weightFactory = new WeightFactory();		// Allocate new weight factory we will read into
		idfLookup = new IDFLookup();				// Allocate new IDF object we will read into
		boolean foundweights = false;
		boolean foundlookup = false;
		XmlElement el = parser.start();
		settings = Integer.decode(el.getAttribute("settings"));
		el = parser.peek();	// The <weightfactory> and <idflookup> tags must be at the second level of the xml
		while(el.isStart()) {
			if ("weightfactory".equals(el.getName())) {
				weightFactory.restoreXml(parser);
				foundweights = true;
			}
			else if ("idflookup".equals(el.getName())) {
				idfLookup.restoreXml(parser);
				foundlookup = true;
			}
			else {
				parser.discardSubTree();
			}
			el = parser.peek();
		}
		if (!foundweights) {
			throw new SAXException("Could not find <weightfactory> tag in configuration");
		}
		if (!foundlookup) {
			throw new SAXException("Could not find <idflookup> tag in configuration");
		}
	}
}
