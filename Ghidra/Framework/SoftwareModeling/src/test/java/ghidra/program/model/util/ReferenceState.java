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
package ghidra.program.model.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.AddressIteratorTestStub;
import ghidra.program.model.ReferenceIteratorTestStub;
import ghidra.program.model.ReferenceManagerTestDouble;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.MemReferenceImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

public class ReferenceState extends ReferenceManagerTestDouble {
	public static final int FUNCTION_BODY_SIZE = 10;
	Map<Address, Set<Address>> fromMap = new HashMap<>();
	Map<Address, Set<Address>> toMap = new HashMap<>();

	void createReference(Address from, Address to) {
        Set<Address> fromSet = fromMap.computeIfAbsent(from, k -> new HashSet<>());
        fromSet.add(to);
        Set<Address> toSet = toMap.computeIfAbsent(to, k -> new HashSet<>());
        toSet.add(from);
	}

	@Override
	public ReferenceIterator getReferencesTo(Address address) {
		Set<Address> set = toMap.get(address);
		List<Reference> list = new ArrayList<>();
		if (set != null) {
			for (Address addr : set) {
				list.add(refer(addr, address));
			}
		}
		return new ReferenceIteratorTestStub(list);
	}

	@Override
	public AddressIterator getReferenceSourceIterator(AddressSetView addrSet, boolean forward) {
		Set<Address> set = new HashSet<>();
		set.add(addrSet.getMinAddress().add(getRandomOffsetInFunctionBody()));
		return new AddressIteratorTestStub(set);
	}

	private int getRandomOffsetInFunctionBody() {
		return (int) (Math.random() * FUNCTION_BODY_SIZE);
	}

	@Override
	public Reference[] getFlowReferencesFrom(Address address) {
		Set<Address> set = fromMap.get(getFunctionAddress(address));
		if (set == null) {
			return new Reference[0];
		}
		Reference[] refs = new Reference[set.size()];
		int i = 0;
		for (Address addr : set) {
			refs[i++] = refer(address, addr);
		}

		return refs;
	}

	private Address getFunctionAddress(Address address) {
		long offset = address.getOffset() & 0xffff00;
		return address.getAddressSpace().getAddress(offset);
	}

	private Reference refer(Address from, Address to) {
		return new MemReferenceImpl(from, to, RefType.UNCONDITIONAL_CALL, SourceType.DEFAULT, 0,
			true);
	}

}
