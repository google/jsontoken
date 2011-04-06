package net.oauth.jsontoken.discovery;

import com.google.common.collect.Lists;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import net.oauth.jsontoken.crypto.RsaSHA256Verifier;
import net.oauth.jsontoken.crypto.Verifier;

import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * Simple certificates finder by fetching from URL. Expects simple json
 * format, for example:
 * {"keyid":"x509 certificate in Pem format", "keyid2":"x509 certificate in Pem format"..}
 */
public class UrlBasedVerifierProvider implements VerifierProvider {

  private final String publicCertUrl;

  public UrlBasedVerifierProvider(String publicCertUrl) {
    this.publicCertUrl = publicCertUrl;
  }

  @Override
  public List<Verifier> findVerifier(String issuer, String keyId) {
    try {
      URL url = new URL(publicCertUrl);
      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("GET");
      if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
        
        InputStreamReader in = new InputStreamReader((InputStream) connection.getContent());
        BufferedReader buff = new BufferedReader(in);
        StringBuffer content = new StringBuffer();
        String line = "";
        do {
          line = buff.readLine();
          content.append(line + "\n");
        } while (line != null);
        
        JsonParser parser = new JsonParser();
        JsonObject jsonObject = parser.parse(content.toString()).getAsJsonObject();
        List<Verifier> verifiers = Lists.newArrayList();
        
        for (Map.Entry<String, JsonElement> cert : jsonObject.entrySet()) {
          String x509PemCertString = cert.getValue().getAsString();
          // Parse pem format
          String[] parts = x509PemCertString.split("\n");
          if (parts.length < 3) {
            return null;
          }
          String x509CertString = "";
          for (int i = 1; i < parts.length - 1; i++) {
            x509CertString += parts[i];
          }
          // parse x509
          byte[] certBytes = Base64.decodeBase64(x509CertString);
          CertificateFactory factory = CertificateFactory.getInstance("X509");
          X509Certificate x509Cert = 
            (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
          verifiers.add(new RsaSHA256Verifier(x509Cert.getPublicKey()));
        }
        return verifiers;  
      } else {
        return null;
      }
    } catch (MalformedURLException e) {
      return null;
    } catch (IOException e) {
      return null;
    } catch (CertificateException e) {
      return null;
    }
  }
}