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
package db.buffers;

import java.io.IOException;
import java.util.NoSuchElementException;

/**
 * <code>BufferFileHandle</code> facilitates access to a BufferFile
 */
public interface BufferFileHandle {

	/**
	 * @see BufferFile#isReadOnly()
	 */
	boolean isReadOnly() throws IOException;

	/**
	 * @see BufferFile#setReadOnly()
	 */
	boolean setReadOnly() throws IOException;

	/**
	 * @see BufferFile#getParameter(java.lang.String)
	 */
	int getParameter(String name) throws NoSuchElementException, IOException;

	/**
	 * @see BufferFile#setParameter(java.lang.String, int)
	 */
	void setParameter(String name, int value) throws IOException;

	/**
	 * @see BufferFile#clearParameters()
	 */
	void clearParameters() throws IOException;

	/**
	 * @see BufferFile#getParameterNames()
	 */
	String[] getParameterNames() throws IOException;

	/**
	 * @see BufferFile#getBufferSize()
	 */
	int getBufferSize() throws IOException;

	/**
	 * @see BufferFile#getIndexCount()
	 */
	int getIndexCount() throws IOException;

	/**
	 * @see BufferFile#getFreeIndexes()
	 */
	int[] getFreeIndexes() throws IOException;

	/**
	 * @see BufferFile#setFreeIndexes(int[])
	 */
	void setFreeIndexes(int[] indexes) throws IOException;

	/**
	 * @see BufferFile#close()
	 */
	void close() throws IOException;

	/**
	 * @see BufferFile#delete() }
	 */
	boolean delete() throws IOException;

	/**
	 * @see BufferFile#get(DataBuffer, int)
	 */
	DataBuffer get(int index) throws IOException;

	/**
	 * @see BufferFile#put(DataBuffer, int)
	 */
	void put(DataBuffer buf, int index) throws IOException;

	/**
	 * @see BufferFile#dispose()
	 */
	void dispose() throws IOException;

	/**
	 * Provides local access to an input block stream.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>false</i>.
	 * @see BufferFileAdapter#getInputBlockStream()
	 */
	InputBlockStream getInputBlockStream() throws IOException;

	/**
	 * Provides local access to an output block stream.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>false</i>.
	 * @see BufferFileAdapter#getOutputBlockStream(int)
	 */
	OutputBlockStream getOutputBlockStream(int blockCount) throws IOException;

	/**
	 * Get an input block stream handle which will facilitate access to a remote InputBlockStream.
	 * The handle will facilitate use of a remote streaming interface.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>true</i>. 
	 * @see BufferFileAdapter#getInputBlockStream()
	 */
	BlockStreamHandle<InputBlockStream> getInputBlockStreamHandle() throws IOException;

	/**
	 * Get an output block stream handle which will facilitate access to a remote InputBlockStream.
	 * The handle will facilitate use of a remote streaming interface.  This method should only be used 
	 * if the associated {@link BufferFileAdapter#isRemote()} is <i>true</i>. 
	 * @see BufferFileAdapter#getOutputBlockStream(int)
	 */
	BlockStreamHandle<OutputBlockStream> getOutputBlockStreamHandle(int blockCount)
			throws IOException;

}
