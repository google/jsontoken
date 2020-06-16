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

import static org.junit.Assert.assertThrows;

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
import java.util.ArrayList;
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

  public void testVerify_valid() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING);
    parser.verify(checkToken, getVerifiers());
  }

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

  public void testVerify_badSignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING_BAD_SIG);
    assertThrows(
        SignatureException.class,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_emptySignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING_EMPTY_SIG);
    assertThrows(
        IllegalStateException.class,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_nullSignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING_2PARTS);
    assertThrows(
        IllegalStateException.class,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_unsupportedSignatureAlgorithm() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
    assertThrows(
        SignatureException.class,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_failChecker() throws Exception {
    JsonTokenParser parser = getJsonTokenParserAlwaysFailChecker();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING);
    assertThrows(
        SignatureException.class,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_noVerifiers() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    List<Verifier> noVerifiers = new ArrayList<>();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING);
    assertThrows(
        SignatureException.class,
        () -> parser.verify(checkToken, noVerifiers)
    );
  }

  public void testVerifyWithJsonToken_valid() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING);
    parser.verify(checkToken);
  }

  public void testVerifyWithJsonToken_unsupportedSignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
    assertThrows(
        IllegalArgumentException.class,
        () -> parser.verify(checkToken)
    );
  }

  public void testVerifyWithJsonTokenOnly_noVerifiers() throws Exception {
    JsonTokenParser parser = getJsonTokenParserNoVerifiers();
    JsonToken checkToken = getJsonTokenToVerify(TOKEN_STRING);
    assertThrows(
        IllegalStateException.class,
        () -> parser.verify(checkToken)
    );
  }

  public void testDeserialize_valid() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken token = parser.deserialize(TOKEN_STRING);

    assertHeader(token);
    assertPayload(token);
  }

  public void testDeserialize_nullIssuer() throws Exception {
    JsonTokenParser parser = getJsonTokenParserNull();
    JsonToken token = parser.deserialize(TOKEN_STRING_ISSUER_NULL);
    assertNull(token.getIssuer());
  }

  public void testDeserialize_badSignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    parser.deserialize(TOKEN_STRING_BAD_SIG);
  }

  public void testDeserialize_noSignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        IllegalStateException.class,
        () -> parser.deserialize(TOKEN_STRING_2PARTS)
    );
  }

  public void testDeserialize_emptySignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        IllegalStateException.class,
        () -> parser.deserialize(TOKEN_STRING_EMPTY_SIG)
    );
  }

  public void testDeserialize_unsupportedSignatureAlgorithm() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    parser.deserialize(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
  }

  public void testDeserialize_headerOnly() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        IllegalStateException.class,
        () -> parser.deserialize(TOKEN_STRING_1PART)
    );
  }

  public void testDeserialize_corruptHeader() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        JsonParseException.class,
        () -> parser.deserialize(TOKEN_STRING_CORRUPT_HEADER)
    );
  }

  public void testDeserialize_corruptPayload() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        JsonParseException.class,
        () -> parser.deserialize(TOKEN_STRING_CORRUPT_PAYLOAD)
    );
  }

  public void testVerifyAndDeserialize_valid() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken token = parser.verifyAndDeserialize(TOKEN_STRING);
    assertHeader(token);
    assertPayload(token);
  }

  public void testVerifyAndDeserialize_deserializeFail() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        JsonParseException.class,
        () -> parser.verifyAndDeserialize(TOKEN_STRING_CORRUPT_PAYLOAD)
    );
  }

  public void testVerifyAndDeserialize_verifyFail() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        SignatureException.class,
        () -> parser.verifyAndDeserialize(TOKEN_STRING_BAD_SIG)
    );
  }

  public void testVerifyAndDeserialize_tokenFromRuby() throws Exception {
    JsonTokenParser parser = getJsonTokenParserLocatorsFromRuby();
    JsonToken token = parser.verifyAndDeserialize(TOKEN_FROM_RUBY);

    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("JWT", token.getHeader().get(JsonToken.TYPE_HEADER).getAsString());
    assertEquals("world", token.getParamAsPrimitive("hello").getAsString());
  }

  public void testSignatureIsValid_valid() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertTrue(parser.signatureIsValid(TOKEN_STRING, getVerifiers()));
  }

  public void testSignatureIsValid_badSignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertFalse(parser.signatureIsValid(TOKEN_STRING_BAD_SIG, getVerifiers()));
  }

  public void testSignatureIsValid_emptySignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        IllegalStateException.class,
        () -> parser.signatureIsValid(TOKEN_STRING_EMPTY_SIG, getVerifiers())
    );
  }

  public void testSignatureIsValid_nullSignature() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    assertThrows(
        IllegalStateException.class,
        () -> parser.signatureIsValid(TOKEN_STRING_2PARTS, getVerifiers())
    );
  }

  public void testExpiration_futureExpiration() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    Instant expiration = clock.now().plus(Duration.standardSeconds(1));
    JsonToken checkToken = getJsonTokenWithTimeRange(null, expiration);

    assertTrue(parser.expirationIsValid(checkToken, clock.now()));
  }

  public void testExpiration_pastExpiration() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    Instant expiration = clock.now().minus(Duration.standardSeconds(1));
    JsonToken checkToken = getJsonTokenWithTimeRange(null, expiration);

    assertFalse(parser.expirationIsValid(checkToken, clock.now()));
  }

  public void testExpiration_nullExpiration() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(null, null);

    assertTrue(parser.expirationIsValid(checkToken, clock.now()));
  }

  public void testIssuedAt_pastIssuedAt() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    Instant issuedAt = clock.now().minus(Duration.standardSeconds(1));
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, null);

    assertTrue(parser.issuedAtIsValid(checkToken, clock.now()));
  }

  public void testIssuedAt_futureIssuedAt() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    Instant issuedAt = clock.now().plus(Duration.standardSeconds(1));
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, null);

    assertFalse(parser.issuedAtIsValid(checkToken, clock.now()));
  }

  public void testIssuedAt_nullIssuedAt() throws Exception {
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(null, null);

    assertTrue(parser.issuedAtIsValid(checkToken, clock.now()));
  }

  public void testPublicKey() throws Exception {
    RsaSHA256Signer signer = new RsaSHA256Signer("google.com", "key1", privateKey);

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setExpiration(clock.now().withDurationAdded(60, 1));

    String tokenString = token.serializeAndSign();

    assertNotNull(token.toString());

    JsonTokenParser parser = getJsonTokenParser();
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

    assertThrows(
        SignatureException.class,
        () -> parser.verifyAndDeserialize(tamperedToken)
    );
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
    JsonTokenParser parser = getJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, expiration);

    try {
      parser.verify(checkToken);
      return true;
    } catch (IllegalStateException e) {
      return false;
    }
  }

  private JsonToken getJsonTokenWithTimeRange(Instant issuedAt, Instant expiration) throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);
    JsonToken token = new JsonToken(signer, clock);
    if (issuedAt != null) {
      token.setIssuedAt(issuedAt);
    }

    if (expiration != null) {
      token.setExpiration(expiration);
    }

    JsonToken checkToken = new JsonToken(
        token.getHeader(),
        token.getPayloadAsJsonObject(),
        clock,
        token.serializeAndSign()
    );

    return checkToken;
  }

  private List<Verifier> getVerifiers() {
    return locators.getVerifierProvider(SignatureAlgorithm.HS256)
        .findVerifier("google.com", "key2");
  }

  private JsonTokenParser getJsonTokenParser() {
    return new JsonTokenParser(clock, locators, new IgnoreAudience());
  }

  private JsonTokenParser getJsonTokenParserAlwaysFailChecker() {
    return new JsonTokenParser(clock, locators, new IgnoreAudience(), new AlwaysFailAudience());
  }

  private JsonTokenParser getJsonTokenParserNoVerifiers() {
    VerifierProvider noLocator = (signerId, keyId) -> null;
    VerifierProviders noLocators = new VerifierProviders();
    noLocators.setVerifierProvider(SignatureAlgorithm.HS256, noLocator);
    return new JsonTokenParser(clock, noLocators, new IgnoreAudience());
  }

  private JsonTokenParser getJsonTokenParserNull() {
    return new JsonTokenParser(null, null);
  }

  private JsonTokenParser getJsonTokenParserLocatorsFromRuby() {
    return new JsonTokenParser(clock, locatorsFromRuby, new IgnoreAudience());
  }
}
