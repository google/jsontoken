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
  
  public static String TOKEN_STRING =
    "key2.LFRh8rIGUGPXpX2KxRet7gcqLkHMFQqQRSomLfdzeEk.eyJpc3N1ZXIiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZGllbmNlIjoiaHR0cDovL3d3dy5nb29nbGUuY29tIiwibm90X2JlZm9yZSI6MTI3NjY2OTcyMjAwMCwibm90X2FmdGVyIjoxMjc2NjY5ODQyMDAwfQ..YmFzZTY0dXJs.SE1BQy1TSEEyNTY";
  
  public FakeClock clock = new FakeClock(Duration.standardMinutes(1));

  @Override
  public void setUp() throws Exception {
    super.setUp();
    clock.setNow(new Instant(1276669722000L));
  }

  public void testCreateJsonToken() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);

    JsonToken token = new JsonToken(signer);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setAudience("http://www.google.com");
    token.setNotBefore(clock.now());
    
    System.out.println(token.serializeAndSign());
    assertEquals(TOKEN_STRING, token.serializeAndSign());
  }
  
  public void testVerification() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_STRING);

    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  public void testPublicKey() throws Exception {

    RsaSHA256Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    JsonToken token = new JsonToken(signer);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");

    String tokenString = token.serializeAndSign();

    assertNotNull(token.toString());

    JsonTokenParser parser = new JsonTokenParser(locators, new IgnoreAudience());
    token = parser.verifyAndDeserialize(tokenString);

    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());

    // now test what happens if we tamper with the token
    JsonObject payload = new JsonParser().parse(
        StringUtils.newStringUsAscii(Base64.decodeBase64(tokenString.split(Pattern.quote("."))[2]))).getAsJsonObject();
    payload.remove("bar");
    payload.addProperty("bar", 14);
    String payloadString = new Gson().toJson(payload);
    String[] parts = tokenString.split("\\.");
    parts[2] = Base64.encodeBase64URLSafeString(payloadString.getBytes());
    assertEquals(6, parts.length);

    String tamperedToken = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + parts[4] + "." + parts[5];
      
    try {
      token = parser.verifyAndDeserialize(tamperedToken);
      fail("verification should have failed");
    } catch (SignatureException e) {
      // expected
    }
  }
}
