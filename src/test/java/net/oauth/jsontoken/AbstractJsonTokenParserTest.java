/**
 * Copyright 2020 Google LLC
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

import com.google.gson.JsonParseException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.exceptions.ErrorCode;
import org.joda.time.Duration;
import org.joda.time.Instant;

public class AbstractJsonTokenParserTest extends JsonTokenTestBase {

  private static final String TOKEN_STRING_ISSUER_NULL = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOm51bGwsImJhciI6MTUsImZvbyI6InNvbWUgdmFsdWUiLCJhdWQiOiJodHRwOi8vd3d3Lmdvb2dsZS5jb20iLCJpYXQiOjEyNzY2Njk3MjIsImV4cCI6MTI3NjY2OTcyM30.WPaa6PoLWPzNfnIBisBX9549kWeABSj9tXnwnPE4IJk";
  private static final String TOKEN_STRING_1PART = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ";
  private static final String TOKEN_STRING_2PARTS = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ";
  private static final String TOKEN_STRING_EMPTY_SIG = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3MiOiJnb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.";
  private static final String TOKEN_STRING_CORRUPT_PAYLOAD = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTIifQ.eyJpc3&&&&&nb29nbGUuY29tIiwiYmFyIjoxNSwiZm9vIjoic29tZSB2YWx1ZSIsImF1ZCI6Imh0dHA6Ly93d3cuZ29vZ2xlLmNvbSIsImlhdCI6MTI3NjY2OTcyMiwiZXhwIjoxMjc2NjY5NzIzfQ.Xugb4nb5kLV3NTpOLaz9er5PhAI5mFehHst_33EUFHs";

  public void testVerify_valid() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);
    parser.verify(checkToken, getVerifiers());
  }

  public void testVerify_issuedAtAfterExpiration() throws Exception {
    Instant issuedAt = clock.now();
    Instant expiration = issuedAt.minus(Duration.standardSeconds(1));
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, expiration);

    assertThrowsWithErrorCode(
        IllegalStateException.class,
        ErrorCode.BAD_TIME_RANGE,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_issuedAtSkew() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.minus(Duration.standardSeconds(1)));
    Instant expiration = issuedAt.plus(Duration.standardSeconds(1));
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, expiration);

    parser.verify(checkToken, getVerifiers());
  }

  public void testVerify_issuedAtTooMuchSkew() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.plus(Duration.standardSeconds(1)));
    Instant expiration = issuedAt.plus(Duration.standardSeconds(1));
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, expiration);

    assertThrowsWithErrorCode(
        IllegalStateException.class,
        ErrorCode.BAD_TIME_RANGE,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_issuedAtNull() throws Exception {
    Instant expiration = clock.now().minus(SKEW.minus(Duration.standardSeconds(1)));
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(null, expiration);

    parser.verify(checkToken, getVerifiers());
  }

  public void testVerify_expirationSkew() throws Exception {
    Instant expiration = clock.now().minus(SKEW.minus(Duration.standardSeconds(1)));
    Instant issuedAt = expiration.minus(Duration.standardSeconds(1));
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, expiration);

    parser.verify(checkToken, getVerifiers());
  }

  public void testVerify_expirationTooMuchSkew() throws Exception {
    Instant expiration = clock.now().minus(SKEW.plus(Duration.standardSeconds(1)));
    Instant issuedAt = expiration.minus(Duration.standardSeconds(1));
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, expiration);

    assertThrowsWithErrorCode(
        IllegalStateException.class,
        ErrorCode.EXPIRED_TOKEN,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_expirationNull() throws Exception {
    Instant issuedAt = clock.now().plus(SKEW.minus(Duration.standardSeconds(1)));
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, null);

    parser.verify(checkToken, getVerifiers());
  }

  public void testVerify_issuedAtNullExpirationNull() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(null, null);

    parser.verify(checkToken, getVerifiers());
  }


  public void testVerify_badSignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_BAD_SIG);
    assertThrowsWithErrorCode(
        SignatureException.class,
        ErrorCode.BAD_SIGNATURE,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_emptySignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_EMPTY_SIG);
    assertThrowsWithErrorCode(
        SignatureException.class,
        ErrorCode.BAD_SIGNATURE,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_nullSignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_2PARTS);
    assertThrowsWithErrorCode(
        IllegalStateException.class,
        ErrorCode.MALFORMED_TOKEN_STRING,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_unsupportedSignatureAlgorithm() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
    // This function does not explicitly check or access the signature algorithm
    assertThrowsWithErrorCode(
        SignatureException.class,
        ErrorCode.BAD_SIGNATURE,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_failChecker() throws Exception {
    AbstractJsonTokenParser parser =
        getAbstractJsonTokenParser(new AlwaysPassChecker(), new AlwaysFailChecker());
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);
    assertThrows(
        SignatureException.class,
        () -> parser.verify(checkToken, getVerifiers())
    );
  }

  public void testVerify_emptyVerifiers() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = naiveDeserialize(TOKEN_STRING);
    assertThrowsWithErrorCode(
        SignatureException.class,
        ErrorCode.BAD_SIGNATURE,
        () -> parser.verify(checkToken, new ArrayList<>())
    );
  }

  public void testDeserialize_valid() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken token = parser.deserialize(TOKEN_STRING);

    assertHeader(token);
    assertPayload(token);
  }

  public void testDeserialize_nullIssuer() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser(null);
    JsonToken token = parser.deserialize(TOKEN_STRING_ISSUER_NULL);
    assertNull(token.getIssuer());
  }

  public void testDeserialize_badSignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    parser.deserialize(TOKEN_STRING_BAD_SIG);
  }

  public void testDeserialize_noSignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    assertThrowsWithErrorCode(
        IllegalStateException.class,
        ErrorCode.MALFORMED_TOKEN_STRING,
        () -> parser.deserialize(TOKEN_STRING_2PARTS)
    );
  }

  public void testDeserialize_emptySignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    parser.deserialize(TOKEN_STRING_EMPTY_SIG);
  }

  public void testDeserialize_unsupportedSignatureAlgorithm() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    parser.deserialize(TOKEN_STRING_UNSUPPORTED_SIGNATURE_ALGORITHM);
  }

  public void testDeserialize_headerOnly() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    assertThrowsWithErrorCode(
        IllegalStateException.class,
        ErrorCode.MALFORMED_TOKEN_STRING,
        () -> parser.deserialize(TOKEN_STRING_1PART)
    );
  }

  public void testDeserialize_corruptHeader() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    assertThrows(
        JsonParseException.class,
        () -> parser.deserialize(TOKEN_STRING_CORRUPT_HEADER)
    );
  }

  public void testDeserialize_corruptPayload() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    assertThrows(
        JsonParseException.class,
        () -> parser.deserialize(TOKEN_STRING_CORRUPT_PAYLOAD)
    );
  }

  public void testSignatureIsValid_valid() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    assertTrue(parser.signatureIsValid(TOKEN_STRING, getVerifiers()));
  }

  public void testSignatureIsValid_badSignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    assertFalse(parser.signatureIsValid(TOKEN_STRING_BAD_SIG, getVerifiers()));
  }

  public void testSignatureIsValid_emptySignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    assertFalse(parser.signatureIsValid(TOKEN_STRING_EMPTY_SIG, getVerifiers()));
  }

  public void testSignatureIsValid_nullSignature() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    assertThrowsWithErrorCode(
        IllegalStateException.class,
        ErrorCode.MALFORMED_TOKEN_STRING,
        () -> parser.signatureIsValid(TOKEN_STRING_2PARTS, getVerifiers())
    );
  }

  public void testExpirationIsValid_futureExpiration() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    Instant expiration = clock.now().plus(Duration.standardSeconds(1));
    JsonToken checkToken = getJsonTokenWithTimeRange(null, expiration);

    assertTrue(parser.expirationIsValid(checkToken, clock.now()));
  }

  public void testExpirationIsValid_pastExpiration() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    Instant expiration = clock.now().minus(Duration.standardSeconds(1));
    JsonToken checkToken = getJsonTokenWithTimeRange(null, expiration);

    assertFalse(parser.expirationIsValid(checkToken, clock.now()));
  }

  public void testExpirationIsValid_nullExpiration() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(null, null);

    assertTrue(parser.expirationIsValid(checkToken, clock.now()));
  }

  public void testIssuedAtIsValid_pastIssuedAt() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    Instant issuedAt = clock.now().minus(Duration.standardSeconds(1));
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, null);

    assertTrue(parser.issuedAtIsValid(checkToken, clock.now()));
  }

  public void testIssuedAtIsValid_futureIssuedAt() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    Instant issuedAt = clock.now().plus(Duration.standardSeconds(1));
    JsonToken checkToken = getJsonTokenWithTimeRange(issuedAt, null);

    assertFalse(parser.issuedAtIsValid(checkToken, clock.now()));
  }

  public void testIssuedAtIsValid_nullIssuedAt() throws Exception {
    AbstractJsonTokenParser parser = getAbstractJsonTokenParser();
    JsonToken checkToken = getJsonTokenWithTimeRange(null, null);

    assertTrue(parser.issuedAtIsValid(checkToken, clock.now()));
  }

  private JsonToken getJsonTokenWithTimeRange(
      Instant issuedAt, Instant expiration) throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);
    JsonToken token = new JsonToken(signer, clock);
    if (issuedAt != null) {
      token.setIssuedAt(issuedAt);
    }

    if (expiration != null) {
      token.setExpiration(expiration);
    }

    return new JsonToken(
        token.getHeader(), token.getPayloadAsJsonObject(), clock, token.serializeAndSign());
  }

  private List<Verifier> getVerifiers() {
    return locators.getVerifierProvider(SignatureAlgorithm.HS256)
        .findVerifier("google.com", "key2");
  }

  private AbstractJsonTokenParser getAbstractJsonTokenParser() {
    return new AbstractJsonTokenParser(clock, new AlwaysPassChecker()){};
  }

  private AbstractJsonTokenParser getAbstractJsonTokenParser(Checker... checkers) {
    return new AbstractJsonTokenParser(clock, checkers){};
  }

}
