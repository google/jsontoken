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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;

import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.joda.time.Duration;
import org.joda.time.Instant;

import java.security.SignatureException;
import java.util.List;
import java.util.regex.Pattern;

public class JsonTokenParserTest extends JsonTokenTestBase {

  private static final String TOKEN_STRING_ISSUER_NULL = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOm51bGwsImJhciI6MTUsImZvbyI6InNvbWUgdmFsdWUiLCJhdWQiOiJodHRwOi8vd3d3Lmdvb2dsZS5jb20iLCJpYXQiOjEyNzY2Njk3MjIsImV4cCI6MTI3NjY2OTcyMn0.jKcuP6BR_-cKpQv2XdFLguYgOxw4ahkZiqjcgrQcm70";
  private static final String TOKEN_STRING_BAD_SIG = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.jKcuP6BR_";
  private static final String TOKEN_STRING_2PARTS = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ";
  private static final String TOKEN_STRING_EMPTY_SIG = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.";
  private static final String TOKEN_STRING_CORRUPT_HEADER = "0yJ0bGci0iJIUzI0NiIsIm0pZCI60mtleT0ifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.jKcuP6BR_-cKpQv2XdFLguYgOxw4ahkZiqjcgrQcm70";
  private static final String TOKEN_STRING_CORRUPT_PAYLOAD = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3&&&&&XtOiJnb290bGUuY20tIiwiYmFyIjoxNSwiZm9vIjoic290ZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIyfQ.jKcuP6BR_-cKpQv2XdFLguYgOxw4ahkZiqjcgrQcm70";
  private static final String TOKEN_FROM_RUBY = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8";

  private boolean testVerifyTimeFrame(Instant issuedAt, Instant expiration) throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);
    JsonToken token = new JsonToken(signer, clock);
    if (issuedAt != null) {
      token.setIssuedAt(issuedAt);
    }
    if (expiration != null) {
      token.setExpiration(expiration);
    }
    token.setAudience("http://www.google.com");

    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken checkToken = parser.deserialize(token.serializeAndSign());
    try {
      parser.verify(checkToken);
      return true;
    } catch (IllegalStateException e) {
      return false;
    }
  }

  public void testVerifyIssuedAtAfterExpiration() throws Exception {
    Instant issuedAt = clock.now();
    Instant expiration = issuedAt.minus(Duration.standardSeconds(1));
    assertFalse(testVerifyTimeFrame(issuedAt, expiration));
  }

  public void testVerifyIssuedAtSkew() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.minus(Duration.standardSeconds(1)));
    Instant expiration = issuedAt.plus(Duration.standardSeconds(1));
    assertTrue(testVerifyTimeFrame(issuedAt, expiration));
  }

  public void testVerifyIssuedAtTooMuchSkew() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.plus(Duration.standardSeconds(1)));
    Instant expiration = issuedAt.plus(Duration.standardSeconds(1));
    assertFalse(testVerifyTimeFrame(issuedAt, expiration));
  }

  public void testVerifyExpirationSkew() throws Exception {
    Instant expiration = clock.now().minus(SKEW.minus(Duration.standardSeconds(1)));
    Instant issuedAt = expiration.minus(Duration.standardSeconds(1));
    assertTrue(testVerifyTimeFrame(issuedAt, expiration));
  }

  public void testVerifyExpirationTooMuchSkew() throws Exception {
    Instant expiration = clock.now().minus(SKEW.plus(Duration.standardSeconds(1)));
    Instant issuedAt = expiration.minus(Duration.standardSeconds(1));
    assertFalse(testVerifyTimeFrame(issuedAt, expiration));
  }

  public void testVerifyIssuedAtNull() throws Exception {
    Instant expiration = clock.now().minus(SKEW.minus(Duration.standardSeconds(1)));
    assertTrue(testVerifyTimeFrame(null, expiration));
  }

  public void testVerifyExpirationNull() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.minus(Duration.standardSeconds(1)));
    assertTrue(testVerifyTimeFrame(issuedAt, null));
  }

  public void testVerifyIssuedAtNullExpirationNull() throws Exception {
    assertTrue((testVerifyTimeFrame(null, null)));
  }

  public void testVerifyFutureToken() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.plus(Duration.standardSeconds(1)));
    Instant expiration = issuedAt.plus(Duration.standardDays(1));
    assertFalse(testVerifyTimeFrame(issuedAt, expiration));
  }

  public void testVerifyPastToken() throws Exception {
    Instant expiration = clock.now().minus(SKEW.plus(Duration.standardSeconds(1)));
    Instant issuedAt = expiration.minus(Duration.standardDays(1));
    assertFalse(testVerifyTimeFrame(issuedAt, expiration));
  }

  private boolean testVerifySignature(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken checkToken = parser.deserialize(tokenString);
    try {
      parser.verify(checkToken);
      return true;
    } catch (SignatureException e) {
      return false;
    }
  }

  private void testVerifySignatureExpectIllegalStateException(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = parser.deserialize(TOKEN_STRING);
    JsonToken testToken = new JsonToken(
        token.getHeader(),
        token.getPayloadAsJsonObject(),
        clock,
        tokenString
    );

    try {
      parser.verify(testToken);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException e) {
      // no-op
    }
  }

  public void testVerifyValidSignature() throws Exception {
    assertTrue(testVerifySignature(TOKEN_STRING));
  }

  public void testVerifyBadSignature() throws Exception {
    assertFalse(testVerifySignature(TOKEN_STRING_BAD_SIG));
  }

  public void testVerifySignatureIsEmpty() throws Exception {
    testVerifySignatureExpectIllegalStateException(TOKEN_STRING_EMPTY_SIG);
  }

  public void testVerifySignatureIsNull() throws Exception {
    testVerifySignatureExpectIllegalStateException(TOKEN_STRING_2PARTS);
  }

  public void testDeserialize() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = parser.deserialize(TOKEN_STRING);

    assertEquals("google.com", token.getIssuer());
    assertEquals("http://www.google.com", token.getAudience());
    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("key2", token.getKeyId());
    assertEquals(new Instant(1276669722000L), token.getIssuedAt());
    assertEquals(new Instant(1276669722000L), token.getExpiration());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  public void testDeserializeNullIssuer() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(null, null);
    JsonToken token = parser.deserialize(TOKEN_STRING_ISSUER_NULL);
    assertNull(token.getIssuer());
  }

  private void deserializeExpectIllegalArgumentException(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    try {
      parser.deserialize(tokenString);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      // no-op
    } catch (IllegalStateException e) {
      // no-op
    }
  }

  public void testDeserializeBadSignature() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    parser.deserialize(TOKEN_STRING_BAD_SIG);
  }

  public void testDeserializeNoSignature() throws Exception {
    deserializeExpectIllegalArgumentException(TOKEN_STRING_2PARTS);
  }

  public void testDeserializeEmptySignature() throws Exception {
    deserializeExpectIllegalArgumentException(TOKEN_STRING_EMPTY_SIG);
  }

  private void deserializeExpectJsonParseException(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    try {
      parser.deserialize(TOKEN_STRING_CORRUPT_HEADER);
      fail("Expected JsonParseException");
    } catch (JsonParseException e) {
      // no-op
    }
  }

  public void testDeserializeCorruptHeader() throws Exception {
    deserializeExpectJsonParseException(TOKEN_STRING_CORRUPT_HEADER);
  }

  public void testDeserializeCorruptPayload() throws Exception {
    deserializeExpectJsonParseException(TOKEN_STRING_CORRUPT_PAYLOAD);
  }

  public void testVerifyAndDeserialize() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_STRING);

    assertEquals("google.com", token.getIssuer());
    assertEquals("http://www.google.com", token.getAudience());
    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("key2", token.getKeyId());
    assertEquals(new Instant(1276669722000L), token.getIssuedAt());
    assertEquals(new Instant(1276669722000L), token.getExpiration());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  public void testVerifyAndDeserializeTokenFromRuby() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locatorsFromRuby, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_FROM_RUBY);
  }

  private boolean testSignature(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    List<Verifier> verifiers = locators.getVerifierProvider(SignatureAlgorithm.HS256)
        .findVerifier("google.com", "key2");
    return parser.signatureIsValid(tokenString, verifiers);
  }

  public void testSignatureIsValid() throws Exception {
    assertTrue(testSignature(TOKEN_STRING));
  }

  public void testSignatureIsBad() throws Exception {
    assertFalse(testSignature(TOKEN_STRING_BAD_SIG));
  }

  private void testSignatureExpectIllegalStateException(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    List<Verifier> verifiers = locators.getVerifierProvider(SignatureAlgorithm.HS256)
        .findVerifier("google.com", "key2");

    try {
      parser.signatureIsValid(tokenString, verifiers);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException e) {
      // no-op
    }
  }

  public void testSignatureIsEmpty() throws Exception {
    testSignatureExpectIllegalStateException(TOKEN_STRING_EMPTY_SIG);
  }

  public void testSignatureIsNull() throws Exception {
    testSignatureExpectIllegalStateException(TOKEN_STRING_2PARTS);
  }

  private boolean testExpiration (Instant expiration) throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);
    JsonToken token = new JsonToken(signer, clock);
    if (expiration != null) {
      token.setExpiration(expiration);
    }

    JsonTokenParser tokenParser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    return tokenParser.expirationIsValid(token, clock.now());
  }

  public void testExpirationInFuture() throws Exception {
    assertTrue(testExpiration(clock.now().plus(Duration.standardSeconds(1))));
  }

  public void testExpirationInPast() throws Exception {
    assertFalse(testExpiration(clock.now().minus(Duration.standardSeconds(1))));
  }

  public void testExpirationIsNull() throws Exception {
    assertTrue(testExpiration(null));
  }

  private boolean testIssuedAt (Instant issuedAt) throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);
    JsonToken token = new JsonToken(signer, clock);
    if (issuedAt != null) {
      token.setIssuedAt(issuedAt);
    }

    JsonTokenParser tokenParser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    return tokenParser.issuedAtIsValid(token, clock.now());
  }

  public void testIssuedAtInPast() throws Exception {
    assertTrue(testIssuedAt(clock.now().minus(Duration.standardSeconds(1))));
  }

  public void testIssuedAtInFuture() throws Exception {
    assertFalse(testIssuedAt(clock.now().plus(Duration.standardSeconds(1))));
  }

  public void testIssuedAtIsNull() throws Exception {
    assertTrue(testIssuedAt(null));
  }

  public void testPublicKey() throws Exception {
    RsaSHA256Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setExpiration(clock.now().withDurationAdded(60, 1));

    String tokenString = token.serializeAndSign();

    assertNotNull(token.toString());

    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    token = parser.verifyAndDeserialize(tokenString);
    assertEquals("google.com", token.getIssuer());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());

    // now test what happens if we tamper with the token
    JsonObject payload = new JsonParser().parse(
        StringUtils.newStringUtf8(Base64.decodeBase64(tokenString.split(Pattern.quote("."))[1])))
        .getAsJsonObject();
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
