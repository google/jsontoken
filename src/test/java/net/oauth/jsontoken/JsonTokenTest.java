package net.oauth.jsontoken;

import net.oauth.jsontoken.crypto.HmacSHA256Signer;

public class JsonTokenTest extends JsonTokenTestBase {

  public void testCreateJsonToken() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer("google.com", "key2", SYMMETRIC_KEY);

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("bar", 15);
    token.setParam("foo", "some value");
    token.setAudience("http://www.google.com");
    token.setIssuedAt(clock.now());
    token.setExpiration(clock.now().withDurationAdded(60, 1));

    assertEquals(TOKEN_STRING, token.serializeAndSign());
  }

  public void testCreateAnotherJsonToken() throws Exception {
    HmacSHA256Signer signer = new HmacSHA256Signer(null, (String) null, "secret".getBytes());

    JsonToken token = new JsonToken(signer, clock);
    token.setParam("hello", "world");
    String encodedToken = token.serializeAndSign();
  }

}
