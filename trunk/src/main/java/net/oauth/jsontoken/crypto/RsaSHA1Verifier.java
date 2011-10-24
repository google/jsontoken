package net.oauth.jsontoken.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class RsaSHA1Verifier implements Verifier {

  private final PublicKey verificationKey;
  private final Signature signer;

  /**
   * Public Constructor.
   * @param verificationKey the key used to verify the signature.
   */
  public RsaSHA1Verifier(PublicKey verificationKey) {
    this.verificationKey = verificationKey;
    try {
      this.signer = Signature.getInstance("SHA1withRSA");
      this.signer.initVerify(verificationKey);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("platform is missing RSAwithSHA1 signature alg", e);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("key is invalid", e);
    }
  }

  @Override
  public void verifySignature(byte[] source, byte[] signature) throws SignatureException {
    try {
      signer.initVerify(verificationKey);
    } catch (InvalidKeyException e) {
      throw new RuntimeException("key someone become invalid since calling the constructor");
    }
    signer.update(source);
    if (!signer.verify(signature)) {
      throw new SignatureException("signature did not verify");
    }
  }
}
