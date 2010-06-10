package net.oauth.jsontoken;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Arrays;

public class HmacSHA256Verifier implements Verifier {

    private final HmacSHA256Signer signer;

    public HmacSHA256Verifier(byte[] verificationKey) throws InvalidKeyException {
        signer = new HmacSHA256Signer(verificationKey);
    }

    @Override
    public void verifySignature(byte[] source, byte[] signature) throws SignatureException {
        byte[] comparison = signer.sign(source);
        if (!Arrays.equals(comparison, signature)) {
            throw new SignatureException("signature did not verify");
        }
    }
}
