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

import org.apache.commons.codec.binary.StringUtils;

import java.security.SignatureException;

/**
 * A Verifier that can verify Strings (as opposed to byte arrays), assuming
 * that the String contains characters in the US-ASCII charset.
 */
public class AsciiStringVerifier {

  private final Verifier verifier;

  /**
   * Public constructor.
   *
   * @param verifier A {@link Verifier} that can verify signatures on byte arrays.
   */
  public AsciiStringVerifier(Verifier verifier) {
    this.verifier = verifier;
  }

  /**
   * Verifies a signature on an ASCII string.
   * @param source the source that was signed.
   * @param signature the signature on the source.
   * @throws SignatureException if the signature doesn't verify.
   */
  public void verifySignature(String source, byte[] signature) throws SignatureException {
    verifier.verifySignature(StringUtils.getBytesUsAscii(source), signature);
  }
}
