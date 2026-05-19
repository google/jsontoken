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
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import javax.annotation.concurrent.ThreadSafe;

/** Signer that can sign byte arrays using RSA and SHA-256. */
@ThreadSafe
public class RsaSHA256Signer extends AbstractSigner {

  private final ThreadLocal<Signature> signature =
      ThreadLocal.withInitial(
          () -> {
            try {
              return Signature.getInstance("SHA256withRSA");
            } catch (NoSuchAlgorithmException e) {
              throw new IllegalStateException("platform is missing RSAwithSHA256 signature alg", e);
            }
          });

  private final PrivateKey signingKey;

  /**
   * Public constructor.
   *
   * @param issuer The id of this signer, to be included in the JSON Token's envelope.
   * @param keyId The id of the key used by this signer, to be included in the JSON Token's
   *     envelope.
   * @param key the private key to be used for signing.
   * @throws InvalidKeyException if the key is unsuitable for RSA signing.
   */
  public RsaSHA256Signer(String issuer, String keyId, RSAPrivateKey key)
      throws InvalidKeyException {
    super(issuer, keyId);

    this.signingKey = key;
    this.signature.get().initSign(signingKey);
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.crypto.Signer#getSignatureAlgorithm()
   */
  @Override
  public SignatureAlgorithm getSignatureAlgorithm() {
    return SignatureAlgorithm.RS256;
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.crypto.Signer#sign(byte[])
   */
  @Override
  public byte[] sign(byte[] source) throws SignatureException {
    Signature sig = signature.get();
    try {
      sig.initSign(signingKey);
    } catch (InvalidKeyException e) {
      throw new RuntimeException("key somehow became invalid since calling the constructor", e);
    }
    sig.update(source);
    return sig.sign();
  }
}
