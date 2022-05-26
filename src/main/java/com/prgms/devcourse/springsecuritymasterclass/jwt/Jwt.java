package com.prgms.devcourse.springsecuritymasterclass.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Jwt {

    private final String issuer;

    private final String clientSecret;

    private final int expirySeconds;

    private final Algorithm algorithm;

    private final JWTVerifier jwtVerifier;


    public Jwt(String issuer, String clientSecret, int expirySeconds) {
        this.issuer = issuer;
        this.clientSecret = clientSecret;
        this.expirySeconds = expirySeconds;
        this.algorithm = Algorithm.HMAC512(clientSecret);
        this.jwtVerifier = com.auth0.jwt.JWT.require(this.algorithm)
                .withIssuer(issuer).build();
    }

    public String sign(Claims claims){
        Date now = new Date();
        Date expireDate = this.expirySeconds > 0 ?
                new Date(now.getTime() + this.expirySeconds * 1000L) :
                new Date(now.getTime());

        return com.auth0.jwt.JWT.create()
                .withIssuer(this.issuer)
                .withIssuedAt(now)
                .withExpiresAt(expireDate)
                .withClaim("username", claims.username)
                .withArrayClaim("roles", claims.roles)
                .sign(this.algorithm);
    }

    public Claims verify(String token){
        return new Claims(jwtVerifier.verify(token));
    }

    public static final class Claims{
        String username;
        String[] roles;
        Date iat;
        Date exp;

        public String getUsername() {
            return username;
        }

        public String[] getRoles() {
            return roles;
        }

        public Date getIat() {
            return iat;
        }

        public Date getExp() {
            return exp;
        }

        private Claims(){/* no op */}

        Claims(DecodedJWT decodedJWT){
            Claim username = decodedJWT.getClaim("username");
            if(!username.isNull())
                this.username = username.asString();
            Claim roles = decodedJWT.getClaim("roles");
            if(!roles.isNull())
                this.roles = roles.asArray(String.class);
            this.iat = decodedJWT.getIssuedAt();
            this.exp = decodedJWT.getExpiresAt();
        }

        public static Claims from(String username, String[] roles){
            Claims claims = new Claims();
            claims.username = username;
            claims.roles = roles;
            return claims;
        }

        public Map<String, Object> toMap(){
            Map<String, Object> map = new HashMap<>();
            map.put("username", username);
            map.put("roles", roles);
            map.put("iat", iat.getTime());
            map.put("exp", exp.getTime());
            return Collections.unmodifiableMap(map);
        }
    }
}
