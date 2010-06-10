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

public class JsonTokenTest extends TestCase {

  private static final byte[] SYMMETRIC_KEY = "kjdhasdkjhaskdjhaskdjhaskdjh".getBytes();

  public void testSignature() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer(SYMMETRIC_KEY);

    Envelope env = new Envelope();
    env.setIssuer("google.com");
    SamplePayload payload = new SamplePayload();
    payload.setBar(15);
    payload.setFoo("some value");
    JsonToken<SamplePayload> token = JsonToken.generateToken(payload, env, signer);

    System.out.println(token.toString());

    assertNotNull(token.toString());
  }

  public void testVerification() throws Exception {
    String tokenString = "eyJmb28iOiJzb21lIHZhbHVlIiwiYmFyIjoxNX0.eyJpc3N1ZXIiOiJnb29nbGUuY29tIn0.sqB9n1ciT1N21wfSdWBJ8BqAgMyu-2qUWpk8i6FirFA";
    HmacSHA256Verifier verifier = new HmacSHA256Verifier(SYMMETRIC_KEY);

    JsonToken<SamplePayload> token = JsonToken.parseToken(tokenString, SamplePayload.class, verifier);

    assertEquals("google.com", token.getEnvelope().getIssuer());
    assertEquals(15, token.getPayload().getBar());
    assertEquals("some value", token.getPayload().getFoo());
  }

  private static class SamplePayload {
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
