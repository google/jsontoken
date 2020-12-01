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
import java.security.SignatureException;

/** A {@link Verifier} that uses HMAC-SHA256 to verify symmetric-key signatures on byte arrays. */
public class HmacSHA256Verifier implements Verifier {

  private final HmacSHA256Signer signer;

  /**
   * Public constructor.
   *
   * @param verificationKey the HMAC verification key to be used for signature verification.
   * @throws InvalidKeyException if the verificationKey cannot be used as an HMAC key.
   */
  public HmacSHA256Verifier(byte[] verificationKey) throws InvalidKeyException {
    signer = new HmacSHA256Signer("verifier", null, verificationKey);
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.crypto.Verifier#verifySignature(byte[], byte[])
   */
  @Override
  public void verifySignature(byte[] source, byte[] signature) throws SignatureException {
    byte[] comparison = signer.sign(source);
    if (!compareBytes(signature, comparison)) {
      throw new SignatureException("signature did not verify");
    }
  }

  /**
   * Performs a byte-by-byte comparison of {@code first} and {@code second} parameters. This method
   * will "NOT" short-circuit the comparison once it has detected a byte difference in order to
   * defend against a "timing attack".
   *
   * @param first the first byte array used in the comparison
   * @param second the second byte array used in the comparison
   * @return {@code true} if the {@code first} and {@code second} byte arrays are equal otherwise
   *     {@code false}
   */
  private boolean compareBytes(byte[] first, byte[] second) {
    if (first == null || second == null) {
      return (first == second);
    } else if (first.length != second.length) {
      return false;
    } else {
      byte result = 0;
      for (int i = 0; i < first.length; i++) {
        result |= first[i] ^ second[i];
      }
      return (result == 0);
    }
  }
}
