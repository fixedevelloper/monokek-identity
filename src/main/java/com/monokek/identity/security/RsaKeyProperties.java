package com.monokek.identity.security;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Holds the RSA keypair used to sign/verify tokens — see AuthorizationServerConfig. */
public record RsaKeyProperties(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

    static RsaKeyProperties fromPem(String privateKeyPem, String publicKeyPem) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        byte[] privateBytes = Base64.getDecoder().decode(strip(privateKeyPem));
        RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));

        byte[] publicBytes = Base64.getDecoder().decode(strip(publicKeyPem));
        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(publicBytes));

        return new RsaKeyProperties(publicKey, privateKey);
    }

    private static String strip(String pem) {
        return pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
    }
}
