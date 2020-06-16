package net.oauth.jsontoken;

import com.google.gson.JsonObject;
import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import org.joda.time.Duration;
import org.joda.time.Instant;

import java.security.SignatureException;

public class JsonTokenTest extends JsonTokenTestBase {

  private static final String TOKEN_STRING_NULL_FIELDS = "eyJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.URnYdSXdAAEukebqZgMq6oFjK4E9cEZlfvO8tBe_WeA";
  private static final String TOKEN_STRING_EMPTY_PAYLOAD = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";

  public void testSignAndSerialize() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setAudience("http://www.google.com");
    token.setIssuedAt(clock.now());
    token.setExpiration(clock.now().plus(Duration.standardSeconds(1)));

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
    try {
      token.serializeAndSign();
      fail("Expected SignatureException");
    } catch (SignatureException e) {
      // expected
    }
  }

  public void testConstructFromJson() throws Exception {
    JsonToken token = new JsonToken(getFullHeader(), getFullPayload(), clock, TOKEN_STRING);
    assertEquals(TOKEN_STRING, token.getTokenString());
    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertEquals("key2", token.getKeyId());
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

  private void assertPayload(JsonToken token) {
    assertEquals("google.com", token.getIssuer());
    assertEquals("http://www.google.com", token.getAudience());
    assertEquals(new Instant(1276669722000L), token.getIssuedAt());
    assertEquals(new Instant(1276669723000L), token.getExpiration());
    assertEquals(15, token.getParamAsPrimitive("bar").getAsLong());
    assertEquals("some value", token.getParamAsPrimitive("foo").getAsString());
  }

  private void assertNullPayload(JsonToken token) throws Exception {
    assertNull(token.getIssuer());
    assertNull(token.getAudience());
    assertEquals(SignatureAlgorithm.HS256, token.getSignatureAlgorithm());
    assertNull(token.getKeyId());
    assertNull(token.getIssuedAt());
    assertNull(token.getExpiration());
  }

}
