package dev.parfenov.jwt_example.models;

import com.nimbusds.jwt.JWTClaimsSet;
import dev.parfenov.jwt_example.services.utils.JwtUtils;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Date;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class JWT {
    UUID jwtId;
    String user;
    Date expirationTime;
    String issuer;
    String telegram;

    public static JWT build(JWTClaimsSet claims) {
        return JWT.builder()
                .user(claims.getSubject())
                .telegram(claims.getClaim(JwtUtils.TELEGRAM).toString())
                .expirationTime(claims.getExpirationTime())
                .issuer(claims.getIssuer())
                .jwtId(UUID.fromString(claims.getJWTID()))
                .build();
    }
}
