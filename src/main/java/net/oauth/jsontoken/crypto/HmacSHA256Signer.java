/*
 * Copyright 2010 Google LLC
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
package net.oauth.jsontoken.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** A signer that can sign byte arrays using HMAC-SHA256. */
public class HmacSHA256Signer extends AbstractSigner {

  private static final String HMAC_SHA256_ALG = "HmacSHA256";

  private final Mac hmac;
  private final SecretKey signingKey;

  /**
   * Public constructor.
   *
   * @param issuer the id of this signer, to be included in the envelope of the JSON token.
   * @param keyId the id of the key that will be included in the envelope. If null, will be omitted
   *     from the envelope.
   * @param keyBytes the actual key.
   * @throws InvalidKeyException if the key cannot be used as an HMAC key.
   */
  public HmacSHA256Signer(String issuer, String keyId, byte[] keyBytes) throws InvalidKeyException {
    super(issuer, keyId);

    this.signingKey = new SecretKeySpec(keyBytes, HMAC_SHA256_ALG);
    try {
      this.hmac = Mac.getInstance(HMAC_SHA256_ALG);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "cannot use Hmac256Signer on system without HmacSHA256 alg", e);
    }

    // just to make sure we catch invalid keys early, let's initialize the hmac and throw if
    // something goes wrong
    hmac.init(signingKey);
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.crypto.Signer#sign(byte[])
   */
  @Override
  public byte[] sign(byte[] source) {
    try {
      hmac.init(signingKey);
    } catch (InvalidKeyException e) {
      // this should not happen - we tested this in the constructor
      throw new IllegalStateException(
          "key somehow became invalid since calling the constructor", e);
    }
    return hmac.doFinal(source);
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.crypto.Signer#getSignatureAlgorithm()
   */
  @Override
  public SignatureAlgorithm getSignatureAlgorithm() {
    return SignatureAlgorithm.HS256;
  }
}
