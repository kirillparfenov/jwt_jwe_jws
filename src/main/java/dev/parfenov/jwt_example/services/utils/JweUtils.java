package dev.parfenov.jwt_example.services.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@UtilityClass
public class JweUtils {

    public JWEHeader jweHeader() {
        return new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                .type(JOSEObjectType.JWT)
                .build();
    }

    @SneakyThrows
    public JWEObject encryptSignedJWE(SignedJWT signedJWT, JWEHeader jweHeader, RSAPublicKey publicKey) {
        var jwe = new JWEObject(jweHeader, new Payload(signedJWT));
        jwe.encrypt(new RSAEncrypter(publicKey));
        return jwe;
    }

    @SneakyThrows
    public EncryptedJWT encryptJWT(JWEHeader header, JWTClaimsSet payload, RSAPublicKey publicKey) {
        var encrypt = new RSAEncrypter(publicKey);
        var jwt = new EncryptedJWT(header, payload);
        jwt.encrypt(encrypt);
        return jwt;
    }

    @SneakyThrows
    public EncryptedJWT parseJWE(String jwe) {
        return EncryptedJWT.parse(JwtUtils.cleanToken(jwe));
    }

    @SneakyThrows
    public EncryptedJWT decrypt(EncryptedJWT encryptedJWT, RSAPrivateKey privateKey) {
        var decrypt = new RSADecrypter(privateKey);
        encryptedJWT.decrypt(decrypt);
        return encryptedJWT;
    }

    @SneakyThrows
    public JWTClaimsSet getClaims(EncryptedJWT decrypted) {
        return decrypted.getJWTClaimsSet();
    }

    @SneakyThrows
    public JWEObject parseSignedJWE(String jweToken) {
        return JWEObject.parse(JwtUtils.cleanToken(jweToken));
    }

    @SneakyThrows
    public JWEObject decryptJWE(JWEObject jwe, RSAPrivateKey privateKey) {
        jwe.decrypt(new RSADecrypter(privateKey));
        return jwe;
    }

    @SneakyThrows
    public SignedJWT parseDecryptedJWE(JWEObject jwe) {
        return jwe.getPayload().toSignedJWT();
    }
}
