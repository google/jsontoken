package net.oauth.jsontoken;

import java.security.SignatureException;

public interface Verifier {

    public void verifySignature(byte[] source, byte[] signature) throws SignatureException;

}
