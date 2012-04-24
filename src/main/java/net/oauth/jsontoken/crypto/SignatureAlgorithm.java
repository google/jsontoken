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

/**
 * Enum of the signature algorithms supported by this package.
 */
public enum SignatureAlgorithm {
  HS256("SHA256"),
  HS1("SHA1"),
  RS256("SHA256"),
  RS1("SHA1");

  private final String hashAlg;

  private SignatureAlgorithm(String hashAlg) {
    this.hashAlg = hashAlg;
  }

  /**
   * What the signature algorithm is named in the "alg" parameter in a JSON Token's envelope.
   */
  public String getNameForJson() {
    return name();
  }

  /**
   * Returns the hash algorithm that should be used when hashing data. When large pieces
   * of data are to be included in a JSON Token's payload, it sometimes might make sense
   * to include the hash of the data instead. If an issuer wants to do that, they should
   * use this hash algorithm to hash the data.
   */
  public String getHashAlgorithm() {
    return hashAlg;
  }

  /**
   * Given the name of the algorithm in the envelope, returns the corresponding enum instance.
   */
  public static SignatureAlgorithm getFromJsonName(String name) {
    return SignatureAlgorithm.valueOf(name);
  }
}
