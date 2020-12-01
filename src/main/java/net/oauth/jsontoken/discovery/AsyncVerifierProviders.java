/*
 * Copyright 2020 Google LLC
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
package net.oauth.jsontoken.discovery;

import javax.annotation.Nullable;
import net.oauth.jsontoken.AsyncJsonTokenParser;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;

/**
 * The asynchronous counterpart of {@link VerifierProviders}. An interface that must be implemented
 * by JSON Token verifiers. The {@link AsyncJsonTokenParser} uses the {@link AsyncVerifierProviders}
 * implementation to locate verification keys. In particular, it will first look up the {@link
 * AsyncVerifierProvider} for the signature algorithm used in the JSON Token and the ask the {@link
 * AsyncVerifierProvider} to provide a future that will return a {@code List<Verifier>} to check the
 * validity of the JSON Token.
 */
public interface AsyncVerifierProviders {

  /**
   * @param alg the signature algorithm of the JSON Token.
   * @return a {@link AsyncVerifierProvider} corresponding to a given signature algorithm that
   *     allows for asynchronous retrieval of a verification key.
   */
  @Nullable
  AsyncVerifierProvider getVerifierProvider(SignatureAlgorithm alg);
}
