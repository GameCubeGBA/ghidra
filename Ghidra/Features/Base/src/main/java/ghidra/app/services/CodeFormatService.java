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
package ghidra.app.services;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * Service provided by a plugin that gives access to a manager for the field formats used by a 
 * listing.
 */
@FunctionalInterface
@ServiceInfo(defaultProvider = CodeBrowserPlugin.class)
public interface CodeFormatService {

	FormatManager getFormatManager();
}
