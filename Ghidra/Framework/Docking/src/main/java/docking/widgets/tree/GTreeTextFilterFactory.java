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
package docking.widgets.tree;

import docking.widgets.filter.FilterOptions;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.util.FilterTransformer;

public interface GTreeTextFilterFactory {
	GTreeFilter getTreeFilter(String filterText, FilterTransformer<GTreeNode> transformer);

	void setFilterOptions(FilterOptions options);

	FilterOptions getFilterOptions();

}
