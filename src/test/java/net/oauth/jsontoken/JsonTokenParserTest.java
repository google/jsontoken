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
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.joda.time.Duration;
import org.joda.time.Instant;

import java.security.SignatureException;
import java.util.List;
import java.util.regex.Pattern;

public class JsonTokenParserTest extends JsonTokenTestBase {

  private static final String TOKEN_STRING_ISSUER_NULL = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOm51bGwsImJhciI6MTUsImZvbyI6InNvbWUgdmFsdWUiLCJhdWQiOiJodHRwOi8vd3d3Lmdvb2dsZS5jb20iLCJpYXQiOjEyNzY2Njk3MjIsImV4cCI6MTI3NjY2OTcyM30.WPaa6PoLWPzNfnIBisBX9549kWeABSj9tXnwnPE4IJk";
  private static final String TOKEN_STRING_BAD_SIG = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.Wugb4nb5kLV3NTpOLaz9er5PhAI5mFehHst_33EUFHs";
  private static final String TOKEN_STRING_1PART = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ";
  private static final String TOKEN_STRING_2PARTS = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ";
  private static final String TOKEN_STRING_EMPTY_SIG = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.";
  private static final String TOKEN_STRING_CORRUPT_HEADER = "fyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.Xugb4nb5kLV3NTpOLaz9er5PhAI5mFehHst_33EUFHs";
  private static final String TOKEN_STRING_CORRUPT_PAYLOAD = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3&&&&&nb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.Xugb4nb5kLV3NTpOLaz9er5PhAI5mFehHst_33EUFHs";
  private static final String TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM = "eyJhbGciOiJIUzUxMiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.44qsiZg1Hnf95N-2wNqd1htgDlE7X0BSUMMkboMcZ5QLKbmVATozMuzdoE0MAhU-IdWUuICFbzu_wcDEXDTLug";
  private static final String TOKEN_FROM_RUBY = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8";

  public void testVerify_issuedAtAfterExpiration() throws Exception {
    Instant issuedAt = clock.now();
    Instant expiration = issuedAt.minus(Duration.standardSeconds(1));
    assertFalse(verifyTimeFrame(issuedAt, expiration));
  }

  public void testVerify_issuedAtSkew() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.minus(Duration.standardSeconds(1)));
    Instant expiration = issuedAt.plus(Duration.standardSeconds(1));
    assertTrue(verifyTimeFrame(issuedAt, expiration));
  }

  public void testVerify_issuedAtTooMuchSkew() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.plus(Duration.standardSeconds(1)));
    Instant expiration = issuedAt.plus(Duration.standardSeconds(1));
    assertFalse(verifyTimeFrame(issuedAt, expiration));
  }

  public void testVerify_issuedAtNull() throws Exception {
    Instant expiration = clock.now().minus(SKEW.minus(Duration.standardSeconds(1)));
    assertTrue(verifyTimeFrame(null, expiration));
  }

  public void testVerify_expirationSkew() throws Exception {
    Instant expiration = clock.now().minus(SKEW.minus(Duration.standardSeconds(1)));
    Instant issuedAt = expiration.minus(Duration.standardSeconds(1));
    assertTrue(verifyTimeFrame(issuedAt, expiration));
  }

  public void testVerify_expirationTooMuchSkew() throws Exception {
    Instant expiration = clock.now().minus(SKEW.plus(Duration.standardSeconds(1)));
    Instant issuedAt = expiration.minus(Duration.standardSeconds(1));
    assertFalse(verifyTimeFrame(issuedAt, expiration));
  }

  public void testVerify_expirationNull() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.minus(Duration.standardSeconds(1)));
    assertTrue(verifyTimeFrame(issuedAt, null));
  }

  public void testVerify_issuedAtNullExpirationNull() throws Exception {
    assertTrue(verifyTimeFrame(null, null));
  }

  public void testVerify_futureToken() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.plus(Duration.standardSeconds(1)));
    Instant expiration = issuedAt.plus(Duration.standardDays(1));
    assertFalse(verifyTimeFrame(issuedAt, expiration));
  }

  public void testVerify_pastToken() throws Exception {
    Instant expiration = clock.now().minus(SKEW.plus(Duration.standardSeconds(1)));
    Instant issuedAt = expiration.minus(Duration.standardDays(1));
    assertFalse(verifyTimeFrame(issuedAt, expiration));
  }

  public void testVerify_validSignature() throws Exception {
    assertTrue(verifySignature(TOKEN_STRING));
  }

  public void testVerify_badSignature() throws Exception {
    assertFalse(verifySignature(TOKEN_STRING_BAD_SIG));
  }

  public void testVerify_emptySignature() throws Exception {
    verifyExpectIllegalStateException(TOKEN_STRING_EMPTY_SIG);
  }

  public void testVerify_nullSignature() throws Exception {
    verifyExpectIllegalStateException(TOKEN_STRING_2PARTS);
  }

  public void testVerify_unsupportedSignatureAlgorithm() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
    try {
      parser.verify(checkToken);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      // expected
    }
  }

  public void testVerify_failChecker() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience(), new AlwaysFailAudience());
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING);
    try {
      parser.verify(checkToken);
      fail("Expected SignatureException");
    } catch (SignatureException e) {
      // expected
    }
  }

  public void testVerify_noVerifiers() throws Exception {
    VerifierProvider failLocator = new VerifierProvider() {
      @Override
      public List<Verifier> findVerifier(String signerId, String keyId) {
        return null;
      }
    };
    VerifierProviders providers = new VerifierProviders();
    providers.setVerifierProvider(SignatureAlgorithm.HS256, failLocator);

    JsonTokenParser parser = new JsonTokenParser(clock, providers, new IgnoreAudience());
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING);
    try {
      parser.verify(checkToken);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException e) {
      // expected
    }
  }

  public void testDeserialize_valid() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = parser.deserialize(TOKEN_STRING);

    assertEquals("google.com", token.getIssuer());
    assertEquals("http://www.google.com", token.getAudience());
    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("key2", token.getKeyId());
    assertEquals(new Instant(1276669722000L), token.getIssuedAt());
    assertEquals(new Instant(1276669723000L), token.getExpiration());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  public void testDeserialize_nullIssuer() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(null, null);
    JsonToken token = parser.deserialize(TOKEN_STRING_ISSUER_NULL);
    assertNull(token.getIssuer());
  }

  public void testDeserialize_badSignature() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    parser.deserialize(TOKEN_STRING_BAD_SIG);
  }

  public void testDeserialize_nullSignature() throws Exception {
    deserializeExpectIllegalStateException(TOKEN_STRING_2PARTS);
  }

  public void testDeserialize_headerOnly() throws Exception {
    deserializeExpectIllegalStateException(TOKEN_STRING_1PART);
  }

  public void testDeserialize_unsupportedSignatureAlgorithm() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience(), new AlwaysFailAudience());
    parser.deserialize(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
  }

  public void testDeserialize_noSignature() throws Exception {
    deserializeExpectIllegalStateException(TOKEN_STRING_2PARTS);
  }

  public void testDeserialize_emptySignature() throws Exception {
    deserializeExpectIllegalStateException(TOKEN_STRING_EMPTY_SIG);
  }

  public void testDeserialize_corruptHeader() throws Exception {
    deserializeExpectJsonParseException(TOKEN_STRING_CORRUPT_HEADER);
  }

  public void testDeserialize_corruptPayload() throws Exception {
    deserializeExpectJsonParseException(TOKEN_STRING_CORRUPT_PAYLOAD);
  }

  public void testVerifyAndDeserialize_valid() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_STRING);

    assertEquals("google.com", token.getIssuer());
    assertEquals("http://www.google.com", token.getAudience());
    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("key2", token.getKeyId());
    assertEquals(new Instant(1276669722000L), token.getIssuedAt());
    assertEquals(new Instant(1276669723000L), token.getExpiration());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  public void testVerifyAndDeserialize_tokenFromRuby() throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locatorsFromRuby, new IgnoreAudience());
    JsonToken token = parser.verifyAndDeserialize(TOKEN_FROM_RUBY);

    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("JWT", token.getHeader().get(JsonToken.TYPE_HEADER).getAsString());
    assertEquals("world", token.getParamAsPrimitive("hello").getAsString());
  }

  public void testSignatureIsValid_valid() throws Exception {
    assertTrue(signatureIsValid(TOKEN_STRING));
  }

  public void testSignatureIsValid_badSignature() throws Exception {
    assertFalse(signatureIsValid(TOKEN_STRING_BAD_SIG));
  }

  public void testSignatureIsValid_emptySignature() throws Exception {
    signatureIsValidExpectIllegalStateException(TOKEN_STRING_EMPTY_SIG);
  }

  public void testSignatureIsValid_nullSignature() throws Exception {
    signatureIsValidExpectIllegalStateException(TOKEN_STRING_2PARTS);
  }

  public void testExpiration_futureExpiration() throws Exception {
    assertTrue(expirationIsValid(clock.now().plus(Duration.standardSeconds(1))));
  }

  public void testExpiration_pastExpiration() throws Exception {
    assertFalse(expirationIsValid(clock.now().minus(Duration.standardSeconds(1))));
  }

  public void testExpiration_nullExpiration() throws Exception {
    assertTrue(expirationIsValid(null));
  }

  public void testIssuedAt_pastIssuedAt() throws Exception {
    assertTrue(issuedAtIsValid(clock.now().minus(Duration.standardSeconds(1))));
  }

  public void testIssuedAt_futureIssuedAt() throws Exception {
    assertFalse(issuedAtIsValid(clock.now().plus(Duration.standardSeconds(1))));
  }

  public void testIssuedAt_nullIssuedAt() throws Exception {
    assertTrue(issuedAtIsValid(null));
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

  private JsonToken getJsonTokenToVerify(String tokenString) {
    // This function only supports a subset of the test token strings
    assertTrue(
        tokenString.equals(TOKEN_STRING)
            || tokenString.equals(TOKEN_STRING_BAD_SIG)
            || tokenString.equals(TOKEN_STRING_EMPTY_SIG)
            || tokenString.equals(TOKEN_STRING_2PARTS)
            || tokenString.equals(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM)
    );

    JsonObject header = getFullHeader();
    if (tokenString.equals(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM)) {
      header.addProperty(JsonToken.ALGORITHM_HEADER, "HS512");
    }
    return new JsonToken(header, getFullPayload(), clock, tokenString);
  }

  private boolean verifyTimeFrame(Instant issuedAt, Instant expiration) throws Exception {
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
    JsonToken checkToken = new JsonToken(
        token.getHeader(),
        token.getPayloadAsJsonObject(),
        clock,
        token.serializeAndSign()
    );

    try {
      parser.verify(checkToken);
      return true;
    } catch (IllegalStateException e) {
      return false;
    }
  }

  private boolean verifySignature(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken checkToken = getJsonTokenToVerify(tokenString);
    try {
      parser.verify(checkToken);
      return true;
    } catch (SignatureException e) {
      return false;
    }
  }

  private void verifyExpectIllegalStateException(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    JsonToken token = getJsonTokenToVerify(TOKEN_STRING);
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
      // expected
    }
  }

  private void deserializeExpectIllegalStateException(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    try {
      parser.deserialize(tokenString);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException e) {
      // expected
    }
  }

  private void deserializeExpectJsonParseException(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    try {
      parser.deserialize(tokenString);
      fail("Expected JsonParseException");
    } catch (JsonParseException e) {
      // expected
    }
  }

  private boolean signatureIsValid(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    List<Verifier> verifiers = locators.getVerifierProvider(SignatureAlgorithm.HS256)
        .findVerifier("google.com", "key2");
    return parser.signatureIsValid(tokenString, verifiers);
  }

  private void signatureIsValidExpectIllegalStateException(String tokenString) throws Exception {
    JsonTokenParser parser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    List<Verifier> verifiers = locators.getVerifierProvider(SignatureAlgorithm.HS256)
        .findVerifier("google.com", "key2");

    try {
      parser.signatureIsValid(tokenString, verifiers);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException e) {
      // expected
    }
  }

  private boolean expirationIsValid(Instant expiration) throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);
    JsonToken token = new JsonToken(signer, clock);
    if (expiration != null) {
      token.setExpiration(expiration);
    }

    JsonTokenParser tokenParser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    return tokenParser.expirationIsValid(token, clock.now());
  }

  private boolean issuedAtIsValid(Instant issuedAt) throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);
    JsonToken token = new JsonToken(signer, clock);
    if (issuedAt != null) {
      token.setIssuedAt(issuedAt);
    }

    JsonTokenParser tokenParser = new JsonTokenParser(clock, locators, new IgnoreAudience());
    return tokenParser.issuedAtIsValid(token, clock.now());
  }
}
