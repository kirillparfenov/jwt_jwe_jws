package dev.parfenov.jwt_example.services.utils;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@UtilityClass
public class JwtUtils {

    public String TELEGRAM = "telegram";
    public String TG_CHANNEL = "https://t.me/parfenov_backend";
    public String WEB = "https://parfenov.dev";

    public JWTClaimsSet buildClaims(String userName) {
        var hour = new Date(Instant.now()
                .plus(1, ChronoUnit.HOURS)
                .atZone(ZoneOffset.UTC)
                .toInstant()
                .toEpochMilli()
        );

        return new JWTClaimsSet.Builder()
                .subject(userName)
                .issuer(WEB)
                .claim(TELEGRAM, TG_CHANNEL)
                .jwtID(UUID.randomUUID().toString())
                .expirationTime(hour)
                .build();
    }

    public String cleanToken(String token) {
        return token.substring(token.indexOf(" ") + 1);
    }
}
