package net.oauth.jsontoken;

import junit.framework.TestCase;

public class JsonTokenTest extends TestCase {

    public void testSignature() {
        Envelope env = new Envelope();
        env.setIssuer("google.com");
        SamplePayload payload = new SamplePayload();
        payload.setBar(15);
        payload.setFoo("some value");
        JsonToken<SamplePayload> token = new JsonToken<SamplePayload>(payload, env);

        System.out.println(token.toString());

        assertNotNull(token.toString());
    }

    public void testVerification() {
        String tokenString = "eyJmb28iOiJzb21lIHZhbHVlIiwiYmFyIjoxNX0.eyJpc3N1ZXIiOiJnb29nbGUuY29tIn0.signature";

        JsonToken<SamplePayload> token = JsonToken.parseToken(tokenString, SamplePayload.class);

        assertEquals("google.com", token.getEnvelope().getIssuer());
        assertEquals(15, token.getPayload().getBar());
        assertEquals("some value", token.getPayload().getFoo());
    }

    private static class SamplePayload {
        private String foo;
        private int bar;

        public String getFoo() {
            return foo;
        }
        public void setFoo(String foo) {
            this.foo = foo;
        }
        public int getBar() {
            return bar;
        }
        public void setBar(int bar) {
            this.bar = bar;
        }
    }
}
