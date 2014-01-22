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
package net.oauth.jsontoken.discovery;

import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.crypto.Verifier;

import java.util.List;

/**
 * An interface that must be implemented by JSON Token verifiers. The {@link JsonTokenParser}
 * uses {@link VerifierProvider} implementations to find verification keys with which to
 * verify the parsed JSON Token. There are different implementations of this interface for
 * different types of verification keys.
 *
 * For symmetric signing keys, an implementation of {@link VerifierProvider} presumably will
 * always look up the key in a local database. For public signing keys, the {@link VerifierProvider}
 * implementation may fetch the public verification keys when needed from the public internet.
 */
public interface VerifierProvider {

  /**
   * Returns the {@link Verifier} that represents a certain verification
   * key, given the key's id and its issuer.
   * @param issuer the id of the issuer that's using the key.
   * @param keyId the id of the key, if keyId mismatches, return a list of 
   * possible verification keys.
   * @return a {@link Verifier} object that represents the verification key.
   */
  public List<Verifier> findVerifier(String issuer, String keyId);

}
