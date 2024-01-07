package dev.parfenov.jwt_example.services.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@UtilityClass
public class JwsUtils {

    public JWSHeader jwsHeader(JWSAlgorithm algorithm) {
        return new JWSHeader.Builder(algorithm)
                .type(JOSEObjectType.JWT)
                .build();
    }

    @SneakyThrows
    public SignedJWT signJWT(JWSHeader header, JWTClaimsSet payload, String secret) {
        var signedJwt = new SignedJWT(header, payload);
        signedJwt.sign(new MACSigner(secret));
        return signedJwt;
    }

    @SneakyThrows
    public SignedJWT signJWT(JWSHeader header, JWTClaimsSet payload, RSAPrivateKey sign) {
        var signedJwt = new SignedJWT(header, payload);
        signedJwt.sign(new RSASSASigner(sign));
        return signedJwt;
    }

    @SneakyThrows
    public SignedJWT parseJWS(String jwsToken) {
        return SignedJWT.parse(JwtUtils.cleanToken(jwsToken));
    }

    @SneakyThrows
    public JWTClaimsSet getClaims(SignedJWT signedJWT) {
        return signedJWT.getJWTClaimsSet();
    }

    @SneakyThrows
    public void validateJWS(SignedJWT jws, String secret) {
        jws.verify(new MACVerifier(secret));
    }

    @SneakyThrows
    public void validateJWS(SignedJWT jws, RSAPublicKey publicKey) {
        jws.verify(new RSASSAVerifier(publicKey));
    }
}
