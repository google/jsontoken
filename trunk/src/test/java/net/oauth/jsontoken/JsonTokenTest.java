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

import java.security.SignatureException;
import java.util.regex.Pattern;

import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.joda.time.Duration;
import org.joda.time.Instant;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class JsonTokenTest extends JsonTokenTestBase {

  public void testSignature() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);

    JsonToken token = new JsonToken(signer);
    token.setTokenLifetime(Duration.standardMinutes(2));
    token.setParam("bar", 15);
    token.setParam("foo", "some value");

    System.out.println(token.toString());
    System.out.println(token.serializeAndSign());

    assertNotNull(token.toString());

    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  public void testVerification() throws Exception {
    String tokenString = "eyJ0b2tlbl9saWZldGltZSI6MTIwMDAwLCJiYXIiOjE1LCJmb28iOiJzb21lIHZhbHVlIiwiaXNzdWVyIjoiZ29vZ2xlLmNvbSIsImtleV9pZCI6ImtleTIiLCJhbGciOiJITUFDLVNIQTI1NiIsIm5vdF9iZWZvcmUiOjEyNzY2Njk3MjEzNDZ9.2ULsBMoQKmdH4PlDkiP2hm_cH0JldIoA9jsEXLt7UfA";

    FakeClock clock = new FakeClock();
    clock.setNow(new Instant(1276669722000L));
    JsonTokenParser parser = new JsonTokenParser(clock, locators);
    JsonToken token = new JsonToken(parser.verifyAndDeserialize(tokenString));

    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  public void testPublicKey() throws Exception {

    RsaSHA256Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    JsonToken token = new JsonToken(signer);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setTokenLifetime(Duration.standardMinutes(1));
    token.setNotBefore(new Instant());

    String tokenString = token.serializeAndSign();

    System.out.println(token.toString());
    System.out.println(tokenString);

    assertNotNull(token.toString());

    JsonTokenParser parser = new JsonTokenParser(locators);
    token = new JsonToken(parser.verifyAndDeserialize(tokenString));

    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());

    // now test what happens if we tamper with the token
    JsonObject payload = new JsonParser().parse(
        StringUtils.newStringUsAscii(Base64.decodeBase64(tokenString.split(Pattern.quote("."))[0]))).getAsJsonObject();
    payload.remove("bar");
    payload.addProperty("bar", 14);
    String payloadString = new Gson().toJson(payload);
    String tamperedToken = tokenString.replaceFirst("[^.]+", Base64.encodeBase64URLSafeString(payloadString.getBytes()));

    System.out.println(tamperedToken);
    try {
      token = new JsonToken(parser.verifyAndDeserialize(tamperedToken));
      fail("verification should have failed");
    } catch (SignatureException e) {
      // expected
    }
  }
}
