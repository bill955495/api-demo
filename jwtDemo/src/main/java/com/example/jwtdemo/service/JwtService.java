package com.example.jwtdemo.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;

/**
 *  JWT 相關的事務
 */
public class JwtService {
    private final SecretKey secretKey; //密鑰
    private final int validSeconds;//JWT的有效期限
    private final JwtParser jwtParser;//JWT解析器，解析和驗收

    public JwtService(String secretKeyStr, int validSeconds) {
        this.secretKey = Keys.hmacShaKeyFor(secretKeyStr.getBytes()); // 建立密鑰
        this.jwtParser = Jwts.parser().verifyWith(secretKey).build();
        this.validSeconds = validSeconds;
    }

    // 創建JWT
    public String createLoginAccessToken(UserDetails user) {
        // 計算過期時間
        long expirationMillis = Instant.now()
                .plusSeconds(validSeconds)
                .getEpochSecond()
                * 1000;

        // 準備 payload 內容
        //聲明(Claim)內容，也就是用來放傳遞訊息的地方
        Claims claims = Jwts.claims()
                .issuedAt(new Date())//JWT 的發行時間
                .expiration(new Date(expirationMillis))//JWT的過期時間
                .add("username", user.getUsername())//and:接受的一方
                .add("authorities", user.getAuthorities()) // 權限
                .build();

        // 簽名後產生 JWT
        return Jwts.builder()
                .claims(claims)
                .signWith(secretKey)
                .compact();
    }

    // 接收 JWT 字串，進行解析，解析失敗，例如過期、不合法，或格式錯誤，則拋出 JwtException。
    public Claims parseToken(String jwt) throws JwtException {
        return jwtParser.parseSignedClaims(jwt).getPayload();
    }
}