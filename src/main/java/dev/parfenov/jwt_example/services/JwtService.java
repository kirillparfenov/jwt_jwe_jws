package dev.parfenov.jwt_example.services;

import com.nimbusds.jose.JWSAlgorithm;
import dev.parfenov.jwt_example.models.JWT;
import dev.parfenov.jwt_example.properties.JwtProperties;
import dev.parfenov.jwt_example.services.utils.JweUtils;
import dev.parfenov.jwt_example.services.utils.JwsUtils;
import dev.parfenov.jwt_example.services.utils.JwtUtils;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;

/**
 * JWT consist of 3 parts: HEADER, PAYLOAD, SIGN
 */
@Service
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class JwtService {

    JwtProperties jwtProperties;
    RsaKeys rsaKeys;

    /**
     * Generate JWS token with symmetric secret-key <br>
     */
    public String generateJWS(String userName) {
        var header = JwsUtils.jwsHeader(JWSAlgorithm.HS256);
        var payload = JwtUtils.buildClaims(userName);
        var sign = JwsUtils.signJWT(header, payload, jwtProperties.secret());

        return sign.serialize();
    }

    public JWT decodeJWS(String token) {
        var signedJWT = JwsUtils.parseJWS(token);
        JwsUtils.validateJWS(signedJWT, jwtProperties.secret());
        var claims = JwsUtils.getClaims(signedJWT);

        return JWT.build(claims);
    }

    /**
     * Generate JWE token
     */
    public String generateJWE(String userName) {
        var header = JweUtils.jweHeader();
        var payload = JwtUtils.buildClaims(userName);
        var encrypted = JweUtils.encryptJWT(header, payload, rsaKeys.publicKey());

        return encrypted.serialize();
    }

    public JWT decodeJWE(String token) {
        var encrypted = JweUtils.parseJWE(token);
        var decrypted = JweUtils.decrypt(encrypted, rsaKeys.privateKey());
        var claims = JweUtils.getClaims(decrypted);

        return JWT.build(claims);
    }

    /**
     * Generate signed JWE token
     */
    public String generateSignedJWE(String userName) {
        var header = JwsUtils.jwsHeader(JWSAlgorithm.RS256);

        var payload = JwtUtils.buildClaims(userName);
        var signed = JwsUtils.signJWT(header, payload, rsaKeys.privateKey());

        var jweHeader = JweUtils.jweHeader();
        var encrypted = JweUtils.encryptSignedJWE(signed, jweHeader, rsaKeys.publicKey());

        return encrypted.serialize();
    }

    public JWT decodeSignedJWE(String token) {
        var jwe = JweUtils.parseSignedJWE(token);
        var decrypted = JweUtils.decryptJWE(jwe, rsaKeys.privateKey());
        var signedJWT = JweUtils.parseDecryptedJWE(decrypted);

        JwsUtils.validateJWS(signedJWT, rsaKeys.publicKey());
        var claims = JwsUtils.getClaims(signedJWT);

        return JWT.build(claims);
    }
}
