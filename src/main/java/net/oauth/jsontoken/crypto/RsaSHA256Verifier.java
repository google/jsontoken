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
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import javax.annotation.concurrent.ThreadSafe;

/** A verifier that can verify signatures on byte arrays using RSA and SHA-256. */
@ThreadSafe
public class RsaSHA256Verifier implements Verifier {

  private final ThreadLocal<Signature> signer =
      ThreadLocal.withInitial(
          () -> {
            try {
              return Signature.getInstance("SHA256withRSA");
            } catch (NoSuchAlgorithmException e) {
              throw new IllegalStateException("platform is missing RSAwithSHA256 signature alg", e);
            }
          });

  private final PublicKey verificationKey;

  /**
   * Public Constructor.
   *
   * @param verificationKey the key used to verify the signature.
   */
  public RsaSHA256Verifier(PublicKey verificationKey) {
    this.verificationKey = verificationKey;
    try {
      this.signer.get().initVerify(verificationKey);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("key is invalid", e);
    }
  }

  /*
   * (non-Javadoc)
   * @see net.oauth.jsontoken.crypto.Verifier#verifySignature(byte[], byte[])
   */
  @Override
  public void verifySignature(byte[] source, byte[] signature) throws SignatureException {
    Signature sig = signer.get();
    try {
      sig.initVerify(verificationKey);
    } catch (InvalidKeyException e) {
      throw new RuntimeException("key someone become invalid since calling the constructor", e);
    }
    sig.update(source);
    if (!sig.verify(signature)) {
      throw new SignatureException("signature did not verify");
    }
  }
}
