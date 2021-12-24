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
/* Generated by Together */

package ghidra.program.model.address;

import java.util.Iterator;

/**
 * Defines a read-only interface for an address set.
 */
public interface AddressSetView extends Iterable<AddressRange> {
	/**
	 * Test if the address is contained within this set.
	 * <P>
	 * @param addr address to test.
	 * @return true if addr exists in the set, false otherwise.
	 */
	boolean contains(Address addr);

	/**
	 * Test if the given address range is contained in this set.
	 * <P>
	 * @param start the first address in the range.
	 * @param end the last address in the range.
	 * @return true if entire range is contained within the set,
	 *         false otherwise.
	 */
	boolean contains(Address start, Address end);

	/**
	 * Test if the given address set is a subset of this set.
	 * <P>
	 * @param rangeSet the set to test.
	 * @return true if the entire set is contained within this set,
	 *         false otherwise.
	 */
	boolean contains(AddressSetView rangeSet);

	/**
	 * @return true if this set is empty.
	 */
	boolean isEmpty();

	/**
	 * @return the minimum address for this set. Returns null if the set is empty.
	 */
	Address getMinAddress();

	/**
	 * @return the maximum address for this set. Returns null if the set is empty.
	 */
	Address getMaxAddress();

	/**
	 * @return the number of address ranges in this set.
	 */
	int getNumAddressRanges();

	/**
	 * @return an iterator over the address ranges in this address set.
	 */
	AddressRangeIterator getAddressRanges();

	/**
	 * Returns an iterator over the ranges in the specified order
	 * @param forward the ranges are returned from lowest to highest, otherwise from
	 * highest to lowest
	 * @return an iterator over all the addresse ranges in the set.
	 */
	AddressRangeIterator getAddressRanges(boolean forward);

	/**
	 * Returns an iterator of address ranges starting with the range that contains the given address.
	 * If there is no range containing the start address, then the the first range will be
	 * the next range greater than the start address if going forward, otherwise the range less than
	 * the start address
	 * @param start the address the the first range should contain.
	 * @param forward true iterators forward, false backwards
	 * @return the AddressRange iterator
	 */
	AddressRangeIterator getAddressRanges(Address start, boolean forward);

	/**
	 * Returns an iterator over the address ranges in this address set.
	 */
	@Override Iterator<AddressRange> iterator();

	/**
	 * Returns an iterator over the ranges in the specified order
	 * @param forward the ranges are returned from lowest to highest, otherwise from
	 * highest to lowest
	 * @return an iterator over all the addresse ranges in the set.
	 */
	Iterator<AddressRange> iterator(boolean forward);

	/**
	 * Returns an iterator of address ranges starting with the range that contains the given address.
	 * If there is no range containing the start address, then the the first range will be
	 * the next range greater than the start address if going forward, otherwise the range less than
	 * the start address
	 * @param start the address the the first range should contain.
	 * @param forward true iterators forward, false backwards
	 * @return the AddressRange iterator
	 */
	Iterator<AddressRange> iterator(Address start, boolean forward);

	/**
	 * @return the number of addresses in this set.
	 */
	long getNumAddresses();

	/**
	 * Returns an iterator over all addresses in this set.
	 * @param forward if true the address are return in increasing order, otherwise in
	 * decreasing order.
	 * @return an iterator over all addresses in this set.
	 */
	AddressIterator getAddresses(boolean forward);

	/**
	 * Returns an iterator over the addresses in this address set
	 * starting at the start address
	 * @param start address to start iterating at in the address set
	 * @param forward if true address are return from lowest to highest, else from highest to lowest
	 * @return an iterator over the addresses in this address set
	 * starting at the start address
	 */
	AddressIterator getAddresses(Address start, boolean forward);

	/**
	 * Determine if this address set intersects with the specified address set.
	 *
	 * @param addrSet address set to check intersection with.
	 * @return true if this set intersects the specified addrSet else false
	 */
	boolean intersects(AddressSetView addrSet);

	/**
	 * Determine if the start and end range
	 * intersects with the specified address set.
	 * @param start start of range
	 * @param end end of range
	 * @return true if the given range intersects this address set.
	 */
	boolean intersects(Address start, Address end);

	/**
	 * Computes the intersection of this address set with the given address set.
	 * This method does not modify this address set.
	 * @param view the address set to intersect with.
	 * @return AddressSet a new address set that contains all addresses that are
	 * contained in both this set and the given set.
	 */
	AddressSet intersect(AddressSetView view);

	/**
	 * Computes the intersection of this address set with the given address range.
	 * This method does not modify this address set.
	 * @param start start of range
	 * @param end end of range
	 * @return AddressSet a new address set that contains all addresses that are
	 * contained in both this set and the given range.
	 */
	AddressSet intersectRange(Address start, Address end);

	/**
	 * Computes the union of this address set with the given address set.  This
	 * method does not change this address set.
	 * @param addrSet The address set to be unioned with this address set.
	 * @return AddressSet A new address set which contains all the addresses
	 * from both this set and the given set.
	 */
	AddressSet union(AddressSetView addrSet);

	/**
	 * Computes the difference of this address set with the given address set
	 * (this - set).  Note that this is not the same as (set - this).  This
	 * method does not change this address set.
	 * @param addrSet the set to subtract from this set.
	 * @return AddressSet a new address set which contains all the addresses
	 * that are in this set, but not in the given set.
	 */
	AddressSet subtract(AddressSetView addrSet);

	/**
	 * Computes the exclusive-or of this address set with the given set. This
	 * method does not modify this address set.
	 * @param addrSet address set to exclusive-or with.
	 * @return AddressSet a new address set containing all addresses that are in
	 * either this set or the given set, but not in both sets
	 */
	AddressSet xor(AddressSetView addrSet);

	/**
	 * Returns true if the given address set contains the same set of addresses
	 * as this set.
	 * @param view the address set to compare.
	 * @return true if the given set contains the same addresses as this set.
	 */
	boolean hasSameAddresses(AddressSetView view);

	/**
	 * Returns the first range in this set or null if the set is empty;
	 * @return the first range in this set or null if the set is empty;
	 */
	AddressRange getFirstRange();

	/**
	 * Returns the last range in this set or null if the set is empty;
	 * @return the last range in this set or null if the set is empty;
	 */
	AddressRange getLastRange();

	/**
	 * Returns the range that contains the given address
	 * @param address the address for which to find a range.
	 * @return the range that contains the given address.
	 */
	AddressRange getRangeContaining(Address address);

	/**
	 * Finds the first address in this collection that is also in the given addressSet.
	 * @param set the addressSet to search for the first (lowest) common address.
	 * @return the first address that is contained in this set and the given set.
	 */
	Address findFirstAddressInCommon(AddressSetView set);

	/**
	 * Trim address set removing all addresses less-than-or-equal to specified 
	 * address based upon {@link Address} comparison.
	 * The address set may contain address ranges from multiple 
	 * address spaces.
	 * @param set address set to be trimmed
	 * @param addr trim point.  Only addresses greater than this address will be returned.
	 * @return trimmed address set view
	 */
	static AddressSetView trimStart(AddressSetView set, Address addr) {
		AddressSet trimmedSet = new AddressSet();
		AddressRangeIterator addressRanges = set.getAddressRanges();
		while (addressRanges.hasNext()) {
			AddressRange range = addressRanges.next();
			Address rangeMin = range.getMinAddress();
			Address rangeMax = range.getMaxAddress();
			if (rangeMin.compareTo(addr) > 0) {
				trimmedSet.add(range);
			}
			else if (rangeMax.compareTo(addr) > 0) {
				trimmedSet.add(addr.next(), rangeMax);

			}
		}
		return trimmedSet;
	}

	/**
	 * Trim address set removing all addresses greater-than-or-equal to specified 
	 * address based upon {@link Address} comparison.  
	 * The address set may contain address ranges from multiple 
	 * address spaces.
	 * @param set address set to be trimmed
	 * @param addr trim point.  Only addresses less than this address will be returned.
	 * @return trimmed address set view
	 */
	static AddressSetView trimEnd(AddressSetView set, Address addr) {
		AddressSet trimmedSet = new AddressSet();
		AddressRangeIterator addressRanges = set.getAddressRanges();
		while (addressRanges.hasNext()) {
			AddressRange range = addressRanges.next();
			Address rangeMin = range.getMinAddress();
			Address rangeMax = range.getMaxAddress();
			if (rangeMax.compareTo(addr) < 0) {
				trimmedSet.add(range);
			}
			else if (rangeMin.compareTo(addr) < 0) {
				trimmedSet.add(rangeMin, addr.previous());
			}
		}
		return trimmedSet;
	}
}
