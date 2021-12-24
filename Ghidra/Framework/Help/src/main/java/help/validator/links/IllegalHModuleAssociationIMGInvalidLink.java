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
package help.validator.links;

import java.io.File;

import help.validator.model.IMG;

public class IllegalHModuleAssociationIMGInvalidLink extends InvalidIMGLink {

	private static final String MESSAGE = "Illegal module association";
	private final File sourceModule;
	private final File destinationModule;

	IllegalHModuleAssociationIMGInvalidLink(IMG img, File sourceModule, File destinationModule) {
		super(img, MESSAGE);
		this.sourceModule = sourceModule;
		this.destinationModule = destinationModule;
	}

	@Override
	public String toString() {
		return message + " - link: " + img + " from file: " + img.getSourceFile().toUri() +
			" (line:" + img.getLineNumber() + ") " + "\"" + sourceModule.getName() + "\"->" + "\"" +
			destinationModule.getName() + "\"";
	}
}
