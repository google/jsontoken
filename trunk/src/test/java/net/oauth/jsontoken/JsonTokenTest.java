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

import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.Duration;
import org.joda.time.Instant;

import java.security.SignatureException;

public class JsonTokenTest extends JsonTokenTestBase {

  public void testSignature() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);

    SamplePayload payload = new SamplePayload();
    payload.setBar(15);
    payload.setFoo("some value");

    JsonTokenBuilder<SamplePayload> builder = JsonTokenBuilder.newBuilder();
    JsonToken<SamplePayload> token = builder
        .setDuration(Duration.standardMinutes(1))
        .setNotBefore(new Instant())
        .setSigner(signer)
        .create(payload);

    System.out.println(token.toString());
    System.out.println(token.getToken());

    assertNotNull(token.toString());
  }

  public void testVerification() throws Exception {
    String tokenString = "eyJmb28iOiJzb21lIHZhbHVlIiwiYmFyIjoxNX0.eyJpc3N1ZXIiOiJnb29nbGUuY29tIiwia2V5X2lkIjoia2V5MiIsImFsZyI6IkhNQUMtU0hBMjU2Iiwibm90X2JlZm9yZSI6MTI3NjIzMzg4NjMwMiwidG9rZW5fbGlmZXRpbWUiOjYwMDAwfQ.9pupBctiHO3oFigwYCDahexJT7U6sckf-oQVQeUiqhk";
    PayloadDeserializer<SamplePayload> deserializer =
        DefaultPayloadDeserializer.newDeserializer(SamplePayload.class);

    FakeClock clock = new FakeClock();
    clock.setNow(new Instant(1276233887000L));
    JsonTokenParser parser = new JsonTokenParser(clock, locators);
    JsonToken<SamplePayload> token = parser.parseToken(tokenString, deserializer);

    assertEquals("google.com", token.getEnvelope().getIssuer());
    assertEquals(15, token.getPayload().getBar());
    assertEquals("some value", token.getPayload().getFoo());
  }

  public void testPublicKey() throws Exception {

    RsaSHA256Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    SamplePayload payload = new SamplePayload();
    payload.setBar(15);
    payload.setFoo("some value");

    JsonTokenBuilder<SamplePayload> builder = JsonTokenBuilder.newBuilder();
    JsonToken<SamplePayload> token = builder
        .setDuration(Duration.standardMinutes(1))
        .setNotBefore(new Instant())
        .setSigner(signer)
        .create(payload);

    String tokenString = token.getToken();

    System.out.println(token.toString());
    System.out.println(tokenString);

    assertNotNull(token.toString());

    PayloadDeserializer<SamplePayload> deserializer =
        DefaultPayloadDeserializer.newDeserializer(SamplePayload.class);
    JsonTokenParser parser = new JsonTokenParser(locators);
    token = parser.parseToken(tokenString, deserializer);

    assertEquals("google.com", token.getEnvelope().getIssuer());
    assertEquals(15, token.getPayload().getBar());
    assertEquals("some value", token.getPayload().getFoo());

    // now test what happens if we tamper with the token
    payload.setBar(14);
    String payloadString = payload.toJson();
    String tamperedToken = tokenString.replaceFirst("[^.]+", Base64.encodeBase64URLSafeString(payloadString.getBytes()));

    System.out.println(tamperedToken);
    try {
      token = parser.parseToken(tamperedToken, deserializer);
      fail("verification should have failed");
    } catch (SignatureException e) {
      // expected
    }
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
