package net.oauth.jsontoken;

import java.security.SignatureException;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;

public class JsonToken<T> {

    static private final String DELIMITER = ".";

    private final T payload;
    private final Envelope envelope;
    private final String signature;

    public static <V> JsonToken<V> parseToken(String tokenString, Class<V> payloadClass,
            Verifier verifier) throws SignatureException {
        String[] pieces = tokenString.split("\\.");
        if (pieces.length != 3) {
            throw new IllegalArgumentException("token did not have three separate parts");
        }
        String payloadString = pieces[0];
        String envelopeString = pieces[1];
        String signature = pieces[2];

        String baseString = payloadString + DELIMITER + envelopeString;
        verifier.verifySignature(baseString.getBytes(), fromBase64(signature).getBytes());

        V payload = fromJson(fromBase64(payloadString), payloadClass);
        Envelope env = fromJson(fromBase64(envelopeString), Envelope.class);

        return new JsonToken<V>(payload, env, signature);
    }

    public static <V> JsonToken<V> generateToken(V payload, Envelope env, Signer signer) {
        String baseString = getBaseString(payload, env);
        String signature = toBase64(signer.sign(baseString.getBytes()));
        return new JsonToken<V>(payload, env, signature);
    }

    private JsonToken(T payload, Envelope envelope, String signature) {
        this.payload = payload;
        this.envelope = envelope;
        this.signature = signature;
    }

    public T getPayload() {
        return payload;
    }

    public Envelope getEnvelope() {
        return envelope;
    }

    private static String toJson(Object obj) {
        return new Gson().toJson(obj);
    }

    private static <V> V fromJson(String json, Class<V> clazz) {
        return new Gson().fromJson(json, clazz);
    }

    private static String toBase64(byte[] source) {
        return new Base64(true).encodeToString(source).trim();
    }

    private static String toBase64(String source) {
        return toBase64(source.getBytes());
    }

    private static String fromBase64(String source) {
        return new String(new Base64(true).decode(source));
    }

    private static <V> String getBaseString(V payload, Envelope envelope) {
        return toBase64(toJson(payload)) + DELIMITER + toBase64(toJson(envelope));
    }

    public String toString() {
        return getBaseString(payload, envelope) + DELIMITER + signature;
    }
}
