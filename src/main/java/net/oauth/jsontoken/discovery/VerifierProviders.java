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

import java.util.Map;

import com.google.common.collect.Maps;

import net.oauth.jsontoken.crypto.SignatureAlgorithm;

public class VerifierProviders {

  private final Map<SignatureAlgorithm, VerifierProvider> map = Maps.newHashMap();

  public void setKeyLocator(SignatureAlgorithm alg, VerifierProvider locator) {
    map.put(alg, locator);
  }

  public VerifierProvider getKeyLocator(SignatureAlgorithm alg) {
    return map.get(alg);
  }
}
