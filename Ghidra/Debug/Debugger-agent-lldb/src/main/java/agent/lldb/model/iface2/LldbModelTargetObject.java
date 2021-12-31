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
package agent.lldb.model.iface2;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.AbstractLldbModel;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.agent.SpiTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.util.datastruct.ListenerSet;

public interface LldbModelTargetObject extends SpiTargetObject {

	@Override
    AbstractLldbModel getModel();

	default CompletableFuture<Void> init(Map<String, Object> map) {
		return CompletableFuture.completedFuture(null);
	}

	default LldbManagerImpl getManager() {
		return (LldbManagerImpl) getModel().getManager();
	}

	default LldbManagerImpl getManagerWithCheck() {
		LldbManagerImpl impl = (LldbManagerImpl) getModel().getManager();
		if (impl == null) {
			return impl;
		}
		return impl;
	}

	Delta<?, ?> changeAttributes(List<String> remove, Map<String, ?> add, String reason);

	CompletableFuture<? extends Map<String, ?>> requestNativeAttributes();

	default CompletableFuture<Void> requestAugmentedAttributes() {
		return AsyncUtils.NIL;
	}

	CompletableFuture<List<TargetObject>> requestNativeElements();

	ListenerSet<DebuggerModelListener> getListeners();

	LldbModelTargetSession getParentSession();

	LldbModelTargetProcess getParentProcess();

	LldbModelTargetThread getParentThread();

	TargetObject getProxy();

	void setModified(Map<String, Object> map, boolean b);

	void setModified(boolean modified);

	void resetModified();

	Object getModelObject();

	void setModelObject(Object modelObject);

	void addMapObject(Object object, TargetObject targetObject);

	TargetObject getMapObject(Object object);

	void deleteMapObject(Object object);
}
