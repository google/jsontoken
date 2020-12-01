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
package net.oauth.jsontoken;

import static org.junit.Assert.assertThrows;

import com.google.gson.JsonObject;
import java.security.SignatureException;
import java.time.Duration;
import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;

public class JsonTokenTest extends JsonTokenTestBase {

  private static final String TOKEN_STRING_NULL_FIELDS =
      "eyJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.URnYdSXdAAEukebqZgMq6oFjK4E9cEZlfvO8tBe_WeA";
  private static final String TOKEN_STRING_EMPTY_PAYLOAD =
      "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";

  public void testSignAndSerialize() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setAudience("http://www.google.com");
    token.setIssuedAt(clock.now());
    token.setExpiration(clock.now().plus(Duration.ofSeconds(1)));

    assertEquals(TOKEN_STRING, token.serializeAndSign());
  }

  public void testSignAndSerialize_nullFields() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer(null, null, "secret".getBytes());

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("hello", "world");

    assertEquals(TOKEN_STRING_NULL_FIELDS, token.serializeAndSign());
  }

  public void testSignAndSerialize_emptyPayload() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer(null, (String) null, "secret".getBytes());
    JsonToken token = new JsonToken(signer, clock);
    assertEquals(TOKEN_STRING_EMPTY_PAYLOAD, token.serializeAndSign());
  }

  public void testSignAndSerialize_tokenFromJson() throws Exception {
    JsonToken token = new JsonToken(getFullHeader(), getFullPayload(), clock, TOKEN_STRING);
    assertThrows(SignatureException.class, () -> token.serializeAndSign());
  }

  public void testConstructFromJson() throws Exception {
    JsonToken token = new JsonToken(getFullHeader(), getFullPayload(), clock, TOKEN_STRING);
    assertEquals(TOKEN_STRING, token.getTokenString());
    assertHeader(token);
    assertPayload(token);
  }

  public void testConstructFromJson_onlyPayload() throws Exception {
    JsonToken token = new JsonToken(getFullPayload(), clock);
    assertPayload(token);
  }

  public void testConstructFromJson_nullFields() throws Exception {
    JsonObject header = new JsonObject();
    header.addProperty(JsonToken.ALGORITHM_HEADER, "HS256");

    JsonObject payload = new JsonObject();
    payload.addProperty("hello", "world");

    JsonToken token = new JsonToken(header, payload, clock, TOKEN_STRING_NULL_FIELDS);
    assertEquals(TOKEN_STRING_NULL_FIELDS, token.getTokenString());
    assertEquals("world", token.getParamAsPrimitive("hello").getAsString());
    assertNullPayload(token);
  }

  public void testConstructFromJson_emptyPayload() throws Exception {
    JsonObject header = new JsonObject();
    header.addProperty(JsonToken.ALGORITHM_HEADER, "HS256");

    JsonObject payload = new JsonObject();

    JsonToken token = new JsonToken(header, payload, clock, TOKEN_STRING_EMPTY_PAYLOAD);
    assertEquals(TOKEN_STRING_EMPTY_PAYLOAD, token.getTokenString());
    assertNullPayload(token);
  }

  private void assertNullPayload(JsonToken token) throws Exception {
    assertNull(token.getIssuer());
    assertNull(token.getAudience());
    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertNull(token.getKeyId());
    assertNull(token.getIssuedAt());
    assertNull(token.getExpiration());
  }

  private JsonObject getFullHeader() {
    JsonObject header = new JsonObject();
    header.addProperty(JsonToken.ALGORITHM_HEADER, "HS256");
    header.addProperty(JsonToken.KEY_ID_HEADER, "key2");
    return header;
  }

  private JsonObject getFullPayload() {
    JsonObject payload = new JsonObject();
    payload.addProperty(JsonToken.ISSUER, "google.com");
    payload.addProperty("bar", 15);
    payload.addProperty("foo", "some value");
    payload.addProperty(JsonToken.AUDIENCE, "http://www.google.com");
    payload.addProperty(JsonToken.ISSUED_AT, 1276669722);
    payload.addProperty(JsonToken.EXPIRATION, 1276669723);
    return payload;
  }
}
