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
package ghidra.framework.plugintool;

import ghidra.framework.plugintool.util.ServiceListener;

/**
 * Interface for providing Services 
 */
public interface ServiceProvider {
	/**
	 * Returns the Service object that implements the given service interface.
	 * @param serviceClass the interface class.
	 */
	<T> T getService(Class<T> serviceClass);
	
	/**
	 * Adds a listener that will be called as services are added and removed from this 
	 * ServiceProvider.
	 * 
	 * @param listener The listener to add.
	 */
	void addServiceListener( ServiceListener listener );
	
	/**
	 * Removes the given listener from this ServiceProvider.  This method does nothing if the
	 * given listener is not contained by this ServiceProvider.
	 * @param listener
	 */
	void removeServiceListener( ServiceListener listener );
}
