package net.oauth.jsontoken;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;

public class JsonToken<T> {

    static private final String DELIMITER = ".";

    private final T payload;
    private final Envelope envelope;

    public static <V> JsonToken<V> parseToken(String tokenString, Class<V> payloadClass) {
        String[] pieces = tokenString.split("\\.");
        if (pieces.length != 3) {
            throw new IllegalArgumentException("token did not have three separate parts");
        }
        String payloadString = pieces[0];
        String envelopeString = pieces[1];

        V payload = fromJson(fromBase64(payloadString), payloadClass);
        Envelope env = fromJson(fromBase64(envelopeString), Envelope.class);

        return new JsonToken<V>(payload, env);
    }

    public JsonToken(T payload, Envelope envelope) {
        this.payload = payload;
        this.envelope = envelope;
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

    private static String toBase64(String source) {
        return new Base64(true).encodeToString(source.getBytes()).trim();
    }

    private static String fromBase64(String source) {
        return new String(new Base64(true).decode(source));
    }

    public String toString() {
        return toBase64(toJson(payload)) + DELIMITER + toBase64(toJson(envelope)) + DELIMITER + "signature";
    }
}
