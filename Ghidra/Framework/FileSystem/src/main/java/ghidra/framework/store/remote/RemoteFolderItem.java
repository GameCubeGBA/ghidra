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
package ghidra.framework.store.remote;

import java.io.IOException;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.FolderItem;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;

/**
 * <code>RemoteFolderItem</code> provides an abstract FolderItem implementation
 * for an item contained within a remote Repository.  
 */
public abstract class RemoteFolderItem implements FolderItem {

	protected String parentPath;
	protected String itemName;
	protected String contentType;
	protected int version;
	protected long versionTime;

	protected RepositoryAdapter repository;

	/**
	 * Construct a FolderItem for an existing repository item.
	 * @param repository repository which contains item
	 * @param item repository item
	 */
	RemoteFolderItem(RepositoryAdapter repository, RepositoryItem item) {
		this.repository = repository;
		parentPath = item.getParentPath();
		itemName = item.getName();
		contentType = item.getContentType();
		version = item.getVersion();
		versionTime = item.getVersionTime();
	}

	/**
	 * Returns the item type as defined by RepositoryItem.
	 * @see ghidra.framework.remote.RepositoryItem
	 */
	abstract int getItemType();

	/*
	 * @see ghidra.framework.store.FolderItem#getName()
	 */
	@Override
	public String getName() {
		return itemName;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#refresh()
	 */
	@Override
	public RemoteFolderItem refresh() throws IOException {
		RepositoryItem item = repository.getItem(parentPath, itemName);
		if (item == null) {
			return null;
		}
		version = item.getVersion();
		versionTime = item.getVersionTime();
		return this;
	}

	/**
	 * @throws IOException 
	 * @see ghidra.framework.store.FolderItem#getFileID()
	 */
	@Override
	public String getFileID() throws IOException {
		RepositoryItem item = repository.getItem(parentPath, itemName);
		if (item != null) {
			return item.getFileID();
		}
		return null;
	}

	/**
	 * @see ghidra.framework.store.FolderItem#resetFileID()
	 */
	@Override
	public String resetFileID() {
		throw new UnsupportedOperationException();
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getContentType()
	 */
	@Override
	public String getContentType() {
		return contentType;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getParentPath()
	 */
	@Override
	public String getParentPath() {
		return parentPath;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getPathName()
	 */
	@Override
	public String getPathName() {
		String path = parentPath;
		if (path.length() != 1) {
			path += FileSystem.SEPARATOR;
		}
		return path + itemName;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#isReadOnly()
	 */
	@Override
	public boolean isReadOnly() {
		throw new UnsupportedOperationException("isReadOnly is not applicable to versioned item");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#setReadOnly(boolean)
	 */
	@Override
	public void setReadOnly(boolean state) {
		throw new UnsupportedOperationException("setReadOnly is not applicable to versioned item");
	}

	/**
	 * Returns the version of content type.  Note this is the version of the structure/storage
	 * for the content type, Not the users version of their data.
	 */
	@Override
	public int getContentTypeVersion() {
		throw new UnsupportedOperationException(
			"getContentTypeVersion is not applicable to versioned item");
	}

	/**
	 * @see ghidra.framework.store.FolderItem#setContentTypeVersion(int)
	 */
	@Override
	public void setContentTypeVersion(int version) throws IOException {
		throw new UnsupportedOperationException(
			"setContentTypeVersion is not applicable to versioned item");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#lastModified()
	 */
	@Override
	public long lastModified() {
		return versionTime;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCurrentVersion()
	 */
	@Override
	public int getCurrentVersion() {
		return version;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#isVersioned()
	 */
	@Override
	public boolean isVersioned() {
		return (version != -1);
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getVersions()
	 */
	@Override
	public Version[] getVersions() throws IOException {
		return repository.getVersions(parentPath, itemName);
	}

	/*
	 * @see ghidra.framework.store.FolderItem#delete(int, java.lang.String)
	 */
	@Override
	public void delete(int ver, String user) throws IOException {
		repository.deleteItem(parentPath, itemName, ver);
	}

	/*
	 * @see ghidra.framework.store.FolderItem#isPrivate()
	 */
	@Override
	public boolean isCheckedOut() {
		throw new UnsupportedOperationException("isCheckedOut is not applicable to versioned item");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#isCheckedOutExclusive()
	 */
	@Override
	public boolean isCheckedOutExclusive() {
		throw new UnsupportedOperationException(
			"isCheckedOutExclusive is not applicable to versioned item");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#checkout(boolean, java.lang.String, java.lang.String)
	 */
	@Override
	public ItemCheckoutStatus checkout(CheckoutType checkoutType, String user, String projectPath)
			throws IOException {
		return repository.checkout(parentPath, itemName, checkoutType, projectPath);
	}

	/*
	 * @see ghidra.framework.store.FolderItem#terminateCheckout(long, boolean)
	 */
	@Override
	public void terminateCheckout(long checkoutId, boolean notify) throws IOException {
		repository.terminateCheckout(parentPath, itemName, checkoutId, notify);
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCheckout(long)
	 */
	@Override
	public ItemCheckoutStatus getCheckout(long checkoutId) throws IOException {
		return repository.getCheckout(parentPath, itemName, checkoutId);
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCheckouts()
	 */
	@Override
	public ItemCheckoutStatus[] getCheckouts() throws IOException {
		return repository.getCheckouts(parentPath, itemName);
	}

	/*
	 * @see ghidra.framework.store.FolderItem#clearCheckout()
	 */
	@Override
	public void clearCheckout() throws IOException {
		throw new UnsupportedOperationException("clearCheckout is not applicable to versioned item");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCheckoutId()
	 */
	@Override
	public long getCheckoutId() throws IOException {
		throw new UnsupportedOperationException("getCheckoutId is not applicable to versioned item");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCheckoutVersion()
	 */
	@Override
	public int getCheckoutVersion() throws IOException {
		throw new UnsupportedOperationException(
			"getCheckoutVersion is not applicable to versioned item");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getLocalCheckoutVersion()
	 */
	@Override
	public int getLocalCheckoutVersion() {
		throw new UnsupportedOperationException(
			"getLocalCheckoutVersion is not applicable to versioned item");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#setCheckout(long, boolean, int, int)
	 */
	@Override
	public void setCheckout(long checkoutId, boolean exclusive, int checkoutVersion,
			int localVersion) throws IOException {
		throw new UnsupportedOperationException("setCheckout is not applicable to versioned item");
	}

}
