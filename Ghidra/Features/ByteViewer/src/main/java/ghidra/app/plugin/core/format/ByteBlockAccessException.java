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
package ghidra.app.plugin.core.format;

import ghidra.util.exception.UsrException;

/**
 * <p>An ByteBlockAccessException indicates that the attempted
 * access is not permitted.  (i.e. Readable/Writeable)</p>
 *
 */
public class ByteBlockAccessException extends UsrException {
    /**
     * <p>Constructs an ByteBlockAccessException with no detail message.<p>
     */
    public ByteBlockAccessException() {
    }
    
    
    /**
     * <p>Constructs an ByteBlockAccessException with the specified
     * detail message.<p>
     *
     * @param message The message.
     */
    public ByteBlockAccessException(String message) {
        super(message);
    }
} 
