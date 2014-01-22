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
import org.apache.commons.codec.binary.StringUtils;

/**
 * A Signer that can sign Strings (as opposed to byte arrays), assuming
 * that the String contains characters in the US-ASCII charset.
 */
public class AsciiStringSigner {

  private final Signer signer;

  /**
   * Public constructor.
   * @param signer {@link Signer} that can sign byte arrays.
   */
  public AsciiStringSigner(Signer signer) {
    this.signer = signer;
  }

  /**
   * Signs the given ASCII string.
   * @throws SignatureException when the signature cannot be generated.
   */
  public byte[] sign(String source) throws SignatureException {
    return signer.sign(StringUtils.getBytesUsAscii(source));
  }
}
