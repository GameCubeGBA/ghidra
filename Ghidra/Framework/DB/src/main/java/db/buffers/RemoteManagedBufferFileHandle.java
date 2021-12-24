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
import java.rmi.Remote;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.NoSuchElementException;

/**
 * <code>RemoteManagedBufferFileHandle</code> facilitates access to a ManagedBufferFile
 * via RMI.
 * <p>
 * Methods from {@link BufferFileHandle} and {@link ManagedBufferFile} <b>must</b> 
 * be re-declared here so they may be properly marshalled for remote invocation via RMI.  
 * This became neccessary with an OpenJDK 11.0.6 change made to 
 * {@link RemoteObjectInvocationHandler}.
 */
public interface RemoteManagedBufferFileHandle extends ManagedBufferFileHandle, Remote {

	//--------------------------------------------------------------------------
	// BufferFileHandle methods
	//--------------------------------------------------------------------------
	@Override boolean isReadOnly() throws IOException;

	@Override boolean setReadOnly() throws IOException;

	@Override int getParameter(String name) throws NoSuchElementException, IOException;

	@Override void setParameter(String name, int value) throws IOException;

	@Override void clearParameters() throws IOException;

	@Override String[] getParameterNames() throws IOException;

	@Override int getBufferSize() throws IOException;

	@Override int getIndexCount() throws IOException;

	@Override int[] getFreeIndexes() throws IOException;

	@Override void setFreeIndexes(int[] indexes) throws IOException;

	@Override void close() throws IOException;

	@Override boolean delete() throws IOException;

	@Override DataBuffer get(int index) throws IOException;

	@Override void put(DataBuffer buf, int index) throws IOException;

	@Override void dispose() throws IOException;

	@Override InputBlockStream getInputBlockStream() throws IOException;

	@Override OutputBlockStream getOutputBlockStream(int blockCount) throws IOException;

	@Override BlockStreamHandle<InputBlockStream> getInputBlockStreamHandle() throws IOException;

	@Override BlockStreamHandle<OutputBlockStream> getOutputBlockStreamHandle(int blockCount)
			throws IOException;

	//--------------------------------------------------------------------------
	// ManagedBufferFileHandle methods
	//--------------------------------------------------------------------------

	@Override ManagedBufferFileHandle getSaveFile() throws IOException;

	@Override void saveCompleted(boolean commit) throws IOException;

	@Override boolean canSave() throws IOException;

	@Override void setVersionComment(String comment) throws IOException;

	@Override BufferFileHandle getNextChangeDataFile(boolean getFirst) throws IOException;

	@Override BufferFileHandle getSaveChangeDataFile() throws IOException;

	@Override long getCheckinID() throws IOException;

	@Override byte[] getForwardModMapData(int oldVersion) throws IOException;

	@Override InputBlockStream getInputBlockStream(byte[] changeMapData) throws IOException;

	@Override BlockStreamHandle<InputBlockStream> getInputBlockStreamHandle(byte[] changeMapData)
			throws IOException;

}
