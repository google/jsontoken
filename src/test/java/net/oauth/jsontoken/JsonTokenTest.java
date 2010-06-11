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
package net.oauth.jsontoken;

import junit.framework.TestCase;

import org.joda.time.Duration;
import org.joda.time.Instant;

public class JsonTokenTest extends TestCase {

  private static final byte[] SYMMETRIC_KEY = "kjdhasdkjhaskdjhaskdjhaskdjh".getBytes();

  public void testSignature() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer(SYMMETRIC_KEY);

    Envelope env = new Envelope();
    env.setIssuer("google.com");
    env.setKeyId("key2");
    env.setNotBefore(new Instant());
    env.setTokenLifetime(Duration.standardMinutes(1));
    env.setSignatureAlgorithm(SignatureAlgorithm.HMAC_SHA256);
    SamplePayload payload = new SamplePayload();
    payload.setBar(15);
    payload.setFoo("some value");
    JsonToken<SamplePayload> token = JsonToken.generateToken(payload, env, signer);

    System.out.println(token.toString());
    System.out.println(token.getToken());

    assertNotNull(token.toString());
  }

  public void testVerification() throws Exception {
    String tokenString = "eyJmb28iOiJzb21lIHZhbHVlIiwiYmFyIjoxNX0.eyJpc3N1ZXIiOiJnb29nbGUuY29tIiwia2V5X2lkIjoia2V5MiIsImFsZyI6IkhNQUNfU0hBMjU2Iiwibm90X2JlZm9yZSI6MTI3NjIxNzg2NjcwMSwidG9rZW5fbGlmZXRpbWUiOjYwMDAwfQ.gG8g3rrXIBKg0dFKxR9cxbvwvSAn-yb1cR3ogpU6ui8";
    HmacSHA256Verifier verifier = new HmacSHA256Verifier(SYMMETRIC_KEY);
    PayloadDeserializer<SamplePayload> deserializer =
        DefaultPayloadDeserializer.newDeserializer(SamplePayload.class);

    JsonToken<SamplePayload> token = JsonToken.parseToken(tokenString, deserializer, verifier);

    assertEquals("google.com", token.getEnvelope().getIssuer());
    assertEquals(15, token.getPayload().getBar());
    assertEquals("some value", token.getPayload().getFoo());
  }

  private static class SamplePayload extends DefaultPayloadImpl {
    private String foo;
    private int bar;

    public String getFoo() {
      return foo;
    }
    public void setFoo(String foo) {
      this.foo = foo;
    }
    public int getBar() {
      return bar;
    }
    public void setBar(int bar) {
      this.bar = bar;
    }
  }
}
