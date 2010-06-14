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
 * Interface that a token signer has to implement. A Signer represents a specific
 * signing key, and knows the id of this key. (The key id is an identifier by
 * which a verifier can find this particular key. It does not need to be
 * globally unique, but must be unique for per token issuer.) A Signer also
 * belongs to a certain issuer: An issuer is the entity that issues tokens, and
 * uses signers to sign them.
 */
public interface Signer {

  /**
   * Returns the id of this signing key. If not null, this will be included in
   * the JSON Token's envelope as the key_id parameter.
   */
  public String getKeyId();

  /**
   * The issuer of the JSON Token. Each signer belongs to an issuer, and an issuer
   * may have one or more signers, each with a distinct key id.
   */
  public String getIssuer();

  /**
   * Returns the signature algorithm used by this signer.
   */
  public SignatureAlgorithm getSignatureAlgorithm();

  /**
   * Signs an array of bytes.
   * @param source The bytes that should be signed.
   * @return The signature on the bytes.
   * @throws SignatureException if the signer could not create the signature.
   */
  public byte[] sign(byte[] source) throws SignatureException;

}
