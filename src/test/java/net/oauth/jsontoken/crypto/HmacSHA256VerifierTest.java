/**
 * Copyright 2012 Google Inc.
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

import junit.framework.TestCase;

import java.security.SignatureException;

import static org.junit.Assert.assertThrows;

/**
 * Basic unit tests for the {@link HmacSHA256Verifier} class.
 */
public class HmacSHA256VerifierTest extends TestCase {
  private static final byte[] SYMMETRIC_KEY = "kjdhasdkjhaskdjhaskdjhaskdjh".getBytes();
  private static final byte[] SOURCE = "randomdatatobesignedfortest".getBytes();

  public void testGoodSignature() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("test", "test-key", SYMMETRIC_KEY);
    HmacSHA256Verifier verifier = new HmacSHA256Verifier(SYMMETRIC_KEY);

    byte[] expectedSignature = signer.sign(SOURCE);
    verifier.verifySignature(SOURCE, expectedSignature);
  }

  public void testBadSignature() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("test", "test-key", SYMMETRIC_KEY);
    HmacSHA256Verifier verifier = new HmacSHA256Verifier(SYMMETRIC_KEY);

    // Generate signature and flip the last bit on the first byte
    byte[] signature = signer.sign(SOURCE);
    signature[0] ^= 1;

    assertThrows(
        SignatureException.class,
        () -> verifier.verifySignature(SOURCE, signature)
    );
  }
}
