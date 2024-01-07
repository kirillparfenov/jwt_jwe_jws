package dev.parfenov.jwt_example.services;

import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.FieldDefaults;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * <strong>generate private key:</strong><br>
 * openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
 * <br>
 * <br><strong>get public key from private:</strong><br>
 * openssl rsa -in private.pem -pubout -out public.pem
 */
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RsaKeys {

    @Value("classpath:private.pem")
    Resource privateKeyPath;
    @Value("classpath:public.pem")
    Resource publicKeyPath;

    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;

    @PostConstruct
    @SneakyThrows
    void buildKeys() {
        var privatePemKey = IOUtils.toString(
                privateKeyPath.getInputStream(),
                StandardCharsets.UTF_8
        );
        var publicPemKey = IOUtils.toString(
                publicKeyPath.getInputStream(),
                StandardCharsets.UTF_8
        );
        privateKey = RSAKey.parseFromPEMEncodedObjects(privatePemKey)
                .toRSAKey()
                .toRSAPrivateKey();
        publicKey = RSAKey.parseFromPEMEncodedObjects(publicPemKey)
                .toRSAKey()
                .toRSAPublicKey();
    }

    public RSAPrivateKey privateKey() {
        return this.privateKey;
    }

    public RSAPublicKey publicKey() {
        return this.publicKey;
    }
}
