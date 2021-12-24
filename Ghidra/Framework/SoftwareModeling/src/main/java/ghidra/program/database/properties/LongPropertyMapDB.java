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
package ghidra.program.database.properties;

import java.io.IOException;

import db.DBHandle;
import db.DBRecord;
import db.LongField;
import db.util.ErrorHandler;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NoValueException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.exception.VersionException;
import ghidra.util.prop.PropertyVisitor;
import ghidra.util.task.TaskMonitor;

/**
 * Property manager that deals with properties that are of
 * long type and stored with a database table.
 */
public class LongPropertyMapDB extends PropertyMapDB implements LongPropertyMap {

	/**
	 * Construct a long property map.
	 * @param dbHandle database handle.
	 * @param openMode the mode that the program was openned in.
	 * @param errHandler database error handler.
	 * @param changeMgr change manager for event notification	 
	 * @param addrMap address map.
	 * @param name property name.
	 * @param monitor progress monitor that is only used when upgrading
	 * @throws VersionException if the database version is not the expected version.
	 * @throws CancelledException if the user cancels the upgrade operation.
	 * @throws IOException if a database io error occurs.
	 */
	public LongPropertyMapDB(DBHandle dbHandle, int openMode, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		super(dbHandle, errHandler, changeMgr, addrMap, name);
		checkMapVersion(openMode, monitor);
	}

	/**
	 * @see ghidra.program.model.util.LongPropertyMap#add(ghidra.program.model.address.Address, long)
	 */
	@Override
	public void add(Address addr, long value) {
		Long oldValue = null;
		lock.acquire();
		try {
			long key = addrMap.getKey(addr, true);
			if (propertyTable == null) {
				createTable(LongField.INSTANCE);
			}
			else {
				oldValue = (Long) cache.get(key);
				if (oldValue == null) {
					DBRecord rec = propertyTable.getRecord(key);
					if (rec != null) {
						oldValue = Long.valueOf(rec.getLongValue(PROPERTY_VALUE_COL));
					}
				}
			}
			DBRecord rec = schema.createRecord(key);
			rec.setLongValue(PROPERTY_VALUE_COL, value);
			propertyTable.putRecord(rec);
			cache.put(key, Long.valueOf(value));
			changeMgr.setPropertyChanged(name, addr, oldValue, Long.valueOf(value));
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.util.LongPropertyMap#getLong(ghidra.program.model.address.Address)
	 */
	@Override
	public long getLong(Address addr) throws NoValueException {
		if (propertyTable == null) {
			throw NO_VALUE_EXCEPTION;
		}

		lock.acquire();
		try {
			long key = addrMap.getKey(addr, false);
			if (key == AddressMap.INVALID_ADDRESS_KEY) {
				return 0;
			}
			Object obj = cache.get(key);
			if (obj != null) {
				return ((Long) obj).longValue();
			}

			DBRecord rec = propertyTable.getRecord(key);
			if (rec == null) {
				throw NO_VALUE_EXCEPTION;
			}
			return rec.getLongValue(PROPERTY_VALUE_COL);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return 0;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getObject(ghidra.program.model.address.Address)
	 */
	@Override
	public Object getObject(Address addr) {
		try {
			return Long.valueOf(getLong(addr));
		}
		catch (NoValueException e) {
			return null;
		}
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#applyValue(ghidra.util.prop.PropertyVisitor, ghidra.program.model.address.Address)
	 */
	@Override
	public void applyValue(PropertyVisitor visitor, Address addr) {
		throw new NotYetImplementedException();
	}

}
