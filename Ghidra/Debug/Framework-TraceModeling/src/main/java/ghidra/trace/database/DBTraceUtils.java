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
package ghidra.trace.database;

import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.google.common.collect.*;

import db.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.RefTypeFactory;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;

public enum DBTraceUtils {
	;

	public static class OffsetSnap {
		public final long offset;
		public final long snap;

		public OffsetSnap(long offset, long snap) {
			this.offset = offset;
			this.snap = snap;
		}

		@Override
		public String toString() {
			return String.format("%d,%08x", snap, offset);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof OffsetSnap)) {
				return false;
			}
			OffsetSnap that = (OffsetSnap) obj;
			if (this.offset != that.offset) {
				return false;
			}
            return this.snap == that.snap;
        }

		@Override
		public int hashCode() {
			return Objects.hash(offset, snap);
		}
	}

	// TODO: Should this be in by default?
	public static class URLDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<URL, OT, StringField> {
		public URLDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(URL.class, objectType, StringField.class, field, column);
		}

		protected String encode(URL url) {
			if (url == null) {
				return null;
			}
			return url.toString();
		}

		@Override
		public void store(URL value, StringField f) {
			f.setString(encode(value));
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setString(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			try {
				String data = record.getString(column);
				if (data == null) {
					setValue(obj, null);
				}
				else {
					setValue(obj, new URL(data));
				}
			}
			catch (MalformedURLException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public static class LanguageIDDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<LanguageID, OT, StringField> {

		public LanguageIDDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(LanguageID.class, objectType, StringField.class, field, column);
		}

		@Override
		public void store(LanguageID value, StringField f) {
			f.setString(value == null ? null : value.getIdAsString());
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			LanguageID id = getValue(obj);
			if (id == null) {
				record.setString(column, null);
			}
			else {
				record.setString(column, id.getIdAsString());
			}
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			String id = record.getString(column);
			if (id == null) {
				setValue(obj, null);
			}
			else {
				setValue(obj, new LanguageID(id));
			}
		}
	}

	public abstract static class AbstractOffsetSnapDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<OffsetSnap, OT, BinaryField> {

		public AbstractOffsetSnapDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(OffsetSnap.class, objectType, BinaryField.class, field, column);
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			OffsetSnap value = getValue(obj);
			if (value == null) {
				record.setBinaryData(column, null);
			}
			else {
				record.setBinaryData(column, encode(value));
			}
		}

		@Override
		public void store(OffsetSnap value, BinaryField f) {
			if (value == null) {
				f.setBinaryData(null);
			}
			else {
				f.setBinaryData(encode(value));
			}
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			byte[] data = record.getBinaryData(column);
			if (data == null) {
				setValue(obj, null);
			}
			else {
				setValue(obj, decode(data));
			}
		}

		protected abstract byte[] encode(OffsetSnap value);

		protected abstract OffsetSnap decode(byte[] arr);
	}

	/**
	 * Codec for storing {@link OffsetSnap}s as {@link BinaryField}s.
	 * 
	 * Encodes the address space ID followed by the address then the snap.
	 *
	 * @param <OT> the type of the object whose field is encoded/decoded.
	 */
	public static class OffsetThenSnapDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractOffsetSnapDBFieldCodec<OT> {

		public OffsetThenSnapDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(objectType, field, column);
		}

		@Override
		protected byte[] encode(OffsetSnap value) {
			// TODO: Can I avoid allocating one on every store?
			ByteBuffer buf = ByteBuffer.allocate(16);
			buf.putLong(value.offset);
			buf.putLong(value.snap ^ Long.MIN_VALUE);
			return buf.array();
		}

		@Override
		protected OffsetSnap decode(byte[] arr) {
			ByteBuffer buf = ByteBuffer.wrap(arr);
			long offset = buf.getLong();
			long snap = buf.getLong() ^ Long.MIN_VALUE;
			return new OffsetSnap(offset, snap);
		}
	}

	public static class RefTypeDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<RefType, OT, ByteField> {
		public RefTypeDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(RefType.class, objectType, ByteField.class, field, column);
		}

		protected byte encode(RefType value) {
			return value == null ? Byte.MIN_VALUE : value.getValue();
		}

		protected RefType decode(byte enc) {
			return enc == Byte.MIN_VALUE ? null : RefTypeFactory.get(enc);
		}

		@Override
		public void store(RefType value, ByteField f) {
			f.setByteValue(encode(value));
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setByteValue(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, decode(record.getByteValue(column)));
		}
	}

	public static abstract class RangeMapSetter<E, D extends Comparable<D>, R, V> {
		protected abstract R getRange(E entry);

		protected abstract V getValue(E entry);

		protected abstract void remove(E entry);

		protected abstract D getLower(R range);

		protected abstract D getUpper(R range);

		protected abstract R toRange(D lower, D upper);

		protected abstract D getPrevious(D d);

		protected abstract D getNext(D d);

		protected abstract Iterable<E> getIntersecting(D lower, D upper);

		protected abstract E put(R range, V value);

		protected D getPreviousOrSame(D d) {
			D prev = getPrevious(d);
			if (prev == null) {
				return d;
			}
			return prev;
		}

		protected D getNextOrSame(D d) {
			D next = getNext(d);
			if (next == null) {
				return d;
			}
			return next;
		}

		protected boolean connects(R r1, R r2) {
			return getPreviousOrSame(getLower(r1)).compareTo(getUpper(r2)) <= 0 ||
				getPreviousOrSame(getLower(r2)).compareTo(getUpper(r1)) <= 0;
		}

		public E set(R range, V value) {
			return set(getLower(range), getUpper(range), value);
		}

		public E set(D lower, D upper, V value) {
			// Go one out to find abutting ranges, too.
			D prev = getPreviousOrSame(lower);
			D next = getNextOrSame(upper);
			Map<R, V> toPut = new HashMap<>();
			for (E entry : getIntersecting(prev, next)) {
				R r = getRange(entry);
				boolean precedesMin = getLower(r).compareTo(lower) < 0;
				boolean succeedsMax = getUpper(r).compareTo(upper) > 0;
				boolean sameVal = Objects.equals(getValue(entry), value);
				if (precedesMin && succeedsMax && sameVal) {
					return entry; // The value in this range is already set as specified
				}
				remove(entry);
				if (precedesMin) {
					if (sameVal) {
						lower = getLower(r);
					}
					else {
						toPut.put(toRange(getLower(r), prev), getValue(entry));
					}
				}
				if (succeedsMax) {
					if (sameVal) {
						upper = getUpper(r);
					}
					else {
						toPut.put(toRange(next, getUpper(r)), getValue(entry));
					}
				}
			}
			E result = put(toRange(lower, upper), value);
			assert toPut.size() <= 2;
			for (Entry<R, V> ent : toPut.entrySet()) {
				put(ent.getKey(), ent.getValue());
			}
			return result;
		}
	}

	public static abstract class AddressRangeMapSetter<E, V>
			extends RangeMapSetter<E, Address, AddressRange, V> {
		@Override
		protected Address getLower(AddressRange range) {
			return range.getMinAddress();
		}

		@Override
		protected Address getUpper(AddressRange range) {
			return range.getMaxAddress();
		}

		@Override
		protected AddressRange toRange(Address lower, Address upper) {
			return new AddressRangeImpl(lower, upper);
		}

		@Override
		protected Address getPrevious(Address d) {
			return d.previous();
		}

		@Override
		protected Address getNext(Address d) {
			return d.next();
		}
	}

	public static abstract class LifespanMapSetter<E, V>
			extends RangeMapSetter<E, Long, Range<Long>, V> {

		@Override
		protected Long getLower(Range<Long> range) {
			return lowerEndpoint(range);
		}

		@Override
		protected Long getUpper(Range<Long> range) {
			return upperEndpoint(range);
		}

		@Override
		protected Range<Long> toRange(Long lower, Long upper) {
			return DBTraceUtils.toRange(lower, upper);
		}

		@Override
		protected Long getPrevious(Long d) {
			if (d == null || d == Long.MIN_VALUE) {
				return null;
			}
			return d - 1;
		}

		@Override
		protected Long getNext(Long d) {
			if (d == null || d == Long.MAX_VALUE) {
				return null;
			}
			return d + 1;
		}
	}

	public static long lowerEndpoint(Range<Long> range) {
		if (!range.hasLowerBound()) {
			return Long.MIN_VALUE;
		}
		if (range.lowerBoundType() == BoundType.CLOSED) {
			return range.lowerEndpoint().longValue();
		}
		return range.lowerEndpoint().longValue() + 1;
	}

	public static long upperEndpoint(Range<Long> range) {
		if (!range.hasUpperBound()) {
			return Long.MAX_VALUE;
		}
		if (range.upperBoundType() == BoundType.CLOSED) {
			return range.upperEndpoint().longValue();
		}
		return range.upperEndpoint().longValue() - 1;
	}

	public static Range<Long> toRange(long lowerEndpoint, long upperEndpoint) {
		if (lowerEndpoint == Long.MIN_VALUE && upperEndpoint == Long.MAX_VALUE) {
			return Range.all();
		}
		if (lowerEndpoint == Long.MIN_VALUE) {
			return Range.atMost(upperEndpoint);
		}
		if (upperEndpoint == Long.MAX_VALUE) {
			return Range.atLeast(lowerEndpoint);
		}
		return Range.closed(lowerEndpoint, upperEndpoint);
	}

	public static Range<Long> toRange(long snap) {
		return toRange(snap, Long.MAX_VALUE);
	}

	public static <T extends Comparable<T>> boolean intersect(Range<T> a, Range<T> b) {
		// Because we're working with a discrete domain, we have to be careful to never use open
		// lower bounds. Otherwise, the following two inputs would cause a true return value when,
		// in fact, the intersection contains no elements: (0, 1], [0, 1).
		return a.isConnected(b) && !a.intersection(b).isEmpty();
	}

	public static <C extends Comparable<C>> int compareRanges(Range<C> a, Range<C> b) {
		int result;
		if (!a.hasLowerBound() && b.hasLowerBound()) {
			return -1;
		}
		if (!b.hasLowerBound() && a.hasLowerBound()) {
			return 1;
		}
		if (a.hasLowerBound()) { // Implies b.hasLowerBound()
			result = a.lowerEndpoint().compareTo(b.lowerEndpoint());
			if (result != 0) {
				return result;
			}
			if (a.lowerBoundType() == BoundType.CLOSED && b.lowerBoundType() == BoundType.OPEN) {
				return -1;
			}
			if (b.lowerBoundType() == BoundType.CLOSED && a.lowerBoundType() == BoundType.OPEN) {
				return 1;
			}
		}

		if (!a.hasUpperBound() && b.hasUpperBound()) {
			return 1;
		}
		if (!b.hasUpperBound() && a.hasUpperBound()) {
			return -1;
		}
		if (a.hasUpperBound()) { // Implies b.hasUpperBound()
			result = a.upperEndpoint().compareTo(b.upperEndpoint());
			if (result != 0) {
				return result;
			}
			if (a.upperBoundType() == BoundType.CLOSED && b.upperBoundType() == BoundType.OPEN) {
				return 1;
			}
			if (b.upperBoundType() == BoundType.CLOSED && a.upperBoundType() == BoundType.OPEN) {
				return -1;
			}
		}
		return 0;
	}

	public static String tableName(String baseName, AddressSpace space, long threadKey,
			int frameLevel) {
		if (space.isRegisterSpace()) {
			if (frameLevel == 0) {
				return baseName + "_" + space.getName() + "_" + threadKey;
			}
			return baseName + "_" + space.getName() + "_" + threadKey + "_" + frameLevel;
		}
		return baseName + "_" + space.getName();
	}

	/**
	 * TODO: Document me
	 * 
	 * Only call this method for entries which definitely intersect the given span
	 * 
	 * @param data
	 * @param span
	 * @param lifespanSetter
	 * @param deleter
	 */
	public static <DR extends AbstractDBTraceAddressSnapRangePropertyMapData<?>> void makeWay(
			DR data, Range<Long> span, BiConsumer<? super DR, Range<Long>> lifespanSetter,
			Consumer<? super DR> deleter) {
		// TODO: Not sure I like this rule....
		if (span.contains(data.getY1())) {
			deleter.accept(data);
			return;
		}
		// NOTE: We know it intersects 
		lifespanSetter.accept(data, toRange(data.getY1(), lowerEndpoint(span) - 1));
	}

	public static List<Range<Long>> subtract(Range<Long> a, Range<Long> b) {
		RangeSet<Long> set = TreeRangeSet.create();
		set.add(a);
		set.remove(b);
		return set.asRanges()
				.stream()
				.map(r -> toRange(lowerEndpoint(r), upperEndpoint(r)))
				.collect(Collectors.toList());
	}

	@SuppressWarnings("unchecked")
	public static <T> Iterator<T> covariantIterator(Iterator<? extends T> it) {
		// Iterators only support read and remove, not insert. Safe to cast.
		return (Iterator<T>) it;
	}

	public static Iterator<Long> iterateSpan(Range<Long> span) {
		return new Iterator<>() {
			final long end = upperEndpoint(span);
			long val = lowerEndpoint(span);

			@Override
			public boolean hasNext() {
				return val <= end;
			}

			@Override
			public Long next() {
				long next = val;
				val++;
				return next;
			}
		};
	}

	public static AddressSetView getAddressSet(AddressFactory factory, Address start,
			boolean forward) {
		AddressSet all = factory.getAddressSet();
		if (forward) {
			Address max = all.getMaxAddress();
			return factory.getAddressSet(start, max);
		}
		Address min = all.getMinAddress();
		return factory.getAddressSet(min, start);
	}

	public static AddressRange toRange(Address min, Address max) {
		if (min.compareTo(max) > 0) {
			throw new IllegalArgumentException("min must precede max");
		}
		return new AddressRangeImpl(min, max);
	}
}
