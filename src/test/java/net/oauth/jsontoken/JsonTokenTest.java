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
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

public class JsonTokenTest extends JsonTokenTestBase {
  
  public static String TOKEN_STRING = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.jKcuP6BR_-cKpQv2XdFLguYgOxw4ahkZiqjcgrQcm70";
  public static String TOKEN_STRING_BAD_SIG = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.jKcuP6BR_";
  public static String TOKEN_STRING_2PARTS = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ";
  public static String TOKEN_STRING_EMPTY_SIG = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.";
  public static String TOKEN_STRING_CORRUPT_HEADER = "0yJ0bGci0iJIUzI0NiIsIm0pZCI60mtleT0ifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.jKcuP6BR_-cKpQv2XdFLguYgOxw4ahkZiqjcgrQcm70";
  public static String TOKEN_STRING_CORRUPT_PAYLOAD = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3&&&&&XtOiJnb290bGUuY20tIiwiYmFyIjoxNSwiZm9vIjoic290ZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.jKcuP6BR_-cKpQv2XdFLguYgOxw4ahkZiqjcgrQcm70";
  public FakeClock clock = new FakeClock(Duration.standardMinutes(1));

  @Override
  public void setUp() throws Exception {
    super.setUp();
    clock.setNow(new Instant(1276669722000L));
  }

  public void testCreateJsonToken() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setAudience("http://www.google.com");
    token.setIssuedAt(clock.now());
    token.setExpiration(clock.now().withDurationAdded(60,1));
    
    assertEquals(TOKEN_STRING, token.serializeAndSign());
  }
  
  public void testDeserializeInvalidToken() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token1 = parser.deserialize(TOKEN_STRING_BAD_SIG);
    deserializeAndExpectIllegalArgument(parser, TOKEN_STRING_2PARTS);
    deserializeAndExpectIllegalArgument(parser, TOKEN_STRING_EMPTY_SIG);
  }
  
  public void testDeserializeCorruptJson() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    try {
      parser.deserialize(TOKEN_STRING_CORRUPT_HEADER);
      fail("Expected JsonParseException");
    } catch(JsonParseException e) {
      // no-op
    }    
    try {
      parser.deserialize(TOKEN_STRING_CORRUPT_PAYLOAD);
      fail("Expected JsonParseException");
    } catch(JsonParseException e) {
      // no-op
    }
  }

  
  private void deserializeAndExpectIllegalArgument(JsonTokenParser parser, 
      String tokenString) throws SignatureException {
    try {
      parser.deserialize(tokenString);
      fail("Expected IllegalArgumentException");
    } catch(IllegalArgumentException e) {
      // no-op
    } catch(IllegalStateException e) {
      // no-op
    }
  }
  
  public void testDeserialize() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = parser.deserialize(TOKEN_STRING);

    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }
  
  public void testVerifyAndDeserialize() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_STRING);

    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  public static String TOKEN_FROM_RUBY = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8";
  public void testVerificationOnTokenFromRuby() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locatorsFromRuby, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_FROM_RUBY);
  }

  public void testCreateAnotherJsonToken() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer(null, (String) null, "secret".getBytes());

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("hello", "world");
    String encodedToken = token.serializeAndSign();
  }

  public void testPublicKey() throws Exception {

    RsaSHA256Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setExpiration(clock.now().withDurationAdded(60,1));

    String tokenString = token.serializeAndSign();

    assertNotNull(token.toString());

    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    token = parser.verifyAndDeserialize(tokenString);
    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());

    // now test what happens if we tamper with the token
    JsonObject payload = new JsonParser().parse(
        StringUtils.newStringUtf8(Base64.decodeBase64(tokenString.split(Pattern.quote("."))[1]))).getAsJsonObject();
    payload.remove("bar");
    payload.addProperty("bar", 14);
    String payloadString = new Gson().toJson(payload);
    String[] parts = tokenString.split("\\.");
    parts[1] = Base64.encodeBase64URLSafeString(payloadString.getBytes());
    assertEquals(3, parts.length);

    String tamperedToken = parts[0] + "." + parts[1] + "." + parts[2];
      
    try {
      token = parser.verifyAndDeserialize(tamperedToken);
      fail("verification should have failed");
    } catch (SignatureException e) {
      // expected
    }
  }
}
