package br.com.travelex.cognito.util;

import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CognitoUtil {
    public static String calculateSecretHash(String clientId, String clientSecret, String username) throws Exception {
        final String HMAC_ALGORITHM = "HmacSHA256";
        SecretKeySpec signingKey = new SecretKeySpec(clientSecret.getBytes(), HMAC_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(signingKey);
        byte[] rawHmac = mac.doFinal((username + clientId).getBytes());
        return Base64.getEncoder().encodeToString(rawHmac);
    }
}
