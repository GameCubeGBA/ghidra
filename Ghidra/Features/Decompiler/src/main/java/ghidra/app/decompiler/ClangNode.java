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
/*
 * Created on Jul 7, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.decompiler;

import ghidra.program.model.address.Address;

import java.awt.Color;
import java.util.List;
/**
 * 
 *
 * Generic tree interface
 */
public interface ClangNode {

	ClangNode Parent();
	Address getMinAddress();
	Address getMaxAddress();
	void setHighlight(Color c);
	int numChildren();
	ClangNode Child(int i);
	ClangFunction getClangFunction();
	void flatten(List<ClangNode> list);

}
