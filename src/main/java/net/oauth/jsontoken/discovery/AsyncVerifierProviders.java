/**
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
 *
 */
package net.oauth.jsontoken.discovery;

import com.google.common.collect.Maps;
import net.oauth.jsontoken.AsyncJsonTokenParser;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import java.util.Map;

/**
 * A collection of {@link AsyncVerifierProvider}s, one for each signature algorithm.
 * The {@link AsyncJsonTokenParser} uses a {@link AsyncVerifierProviders} instance to locate
 * verification keys. In particular, it will first look up the {@link AsyncVerifierProvider}
 * for the signature algorithm used in the JSON Token (different signature methods
 * will use different ways to look up verification keys - for example, symmetric keys
 * will always be pre-negotiated and looked up in a local database, while public
 * verification keys can be looked up on demand), and the ask the {@link AsyncVerifierProvider}
 * to provide a {@link Verifier} to check the validity of the JSON Token.
 */
public class AsyncVerifierProviders {

  private final Map<SignatureAlgorithm, AsyncVerifierProvider> map = Maps.newHashMap();

  /**
   * Sets a new {@link AsyncVerifierProvider} for the given {@link SignatureAlgorithm}.
   */
  public void setVerifierProvider(SignatureAlgorithm alg, AsyncVerifierProvider provider) {
    map.put(alg, provider);
  }

  /**
   * Returns the {@link AsyncVerifierProvider} for the given {@link SignatureAlgorithm}.
   */
  public AsyncVerifierProvider getVerifierProvider(SignatureAlgorithm alg) {
    return map.get(alg);
  }
}
