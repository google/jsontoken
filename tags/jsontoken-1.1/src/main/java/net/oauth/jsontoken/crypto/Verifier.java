/**
 * Copyright 2010 Google Inc.
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
 *
 */
package net.oauth.jsontoken.crypto;

import java.security.SignatureException;

/**
 * Interface that a JSON Token verifier has to implement.
 */
public interface Verifier {

  /**
   * Verifies a signature on an array of bytes.
   * @param source The bytes that were signed.
   * @param signature The signature on the bytes.
   * @throws SignatureException If the signature doesn't match, or if some other error occurred.
   */
  public void verifySignature(byte[] source, byte[] signature) throws SignatureException;

}
