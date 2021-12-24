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
package ghidra.program.database;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface IntRangeMap {

	void setValue(AddressSetView addresses, int value);

	void setValue(Address start, Address end, int value);

	Integer getValue(Address address);

	AddressSet getAddressSet();

	AddressSet getAddressSet(int value);

	void clearValue(AddressSetView addresses);

	void clearValue(Address start, Address end);

	void clearAll();

	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException;
}
