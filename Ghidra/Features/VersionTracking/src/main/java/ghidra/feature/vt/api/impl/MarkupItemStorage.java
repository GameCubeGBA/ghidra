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
package ghidra.feature.vt.api.impl;

import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMarkupItemStatus;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.address.Address;

public interface MarkupItemStorage {

	VTMarkupType getMarkupType();

	VTAssociation getAssociation();

	Address getSourceAddress();

	Address getDestinationAddress();

	String getDestinationAddressSource();

	VTMarkupItemStatus getStatus();

	String getStatusDescription();

	Stringable getSourceValue();

	Stringable getDestinationValue();

	MarkupItemStorage setStatus(VTMarkupItemStatus status);

	MarkupItemStorage reset();

	MarkupItemStorage setDestinationAddress(Address address, String addressSource);

	MarkupItemStorage setApplyFailed(String message);

	void setSourceDestinationValues(Stringable sourceValue, Stringable destinationValue);

}
