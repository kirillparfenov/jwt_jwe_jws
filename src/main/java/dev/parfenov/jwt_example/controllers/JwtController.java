package dev.parfenov.jwt_example.controllers;

import dev.parfenov.jwt_example.models.JWT;
import dev.parfenov.jwt_example.services.JwtService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/jwt")
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class JwtController {

    JwtService jwtService;

    @ResponseStatus(HttpStatus.CREATED)
    @GetMapping("/generate/jws/user/{userName}")
    public String generateJWS(@PathVariable String userName) {
        return jwtService.generateJWS(userName);
    }

    @ResponseStatus(HttpStatus.OK)
    @GetMapping(value = "/decode/jws/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public JWT decodeJWSToken(@RequestHeader(value = HttpHeaders.AUTHORIZATION) String jwsToken) {
        return jwtService.decodeJWS(jwsToken);
    }

    @ResponseStatus(HttpStatus.CREATED)
    @GetMapping("/generate/jwe/user/{userName}")
    public String generateJWE(@PathVariable String userName) {
        return jwtService.generateJWE(userName);
    }

    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/decode/jwe/token")
    public JWT decodeJWEToken(@RequestHeader(value = HttpHeaders.AUTHORIZATION) String jweToken) {
        return jwtService.decodeJWE(jweToken);
    }

    @ResponseStatus(HttpStatus.CREATED)
    @GetMapping("/generate/signed/jwe/user/{userName}")
    public String generateSignedJWE(@PathVariable String userName) {
        return jwtService.generateSignedJWE(userName);
    }

    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/decode/signed/jwe/token")
    public JWT decodeSignedJWEToken(@RequestHeader(value = HttpHeaders.AUTHORIZATION) String jweToken) {
        return jwtService.decodeSignedJWE(jweToken);
    }
}
