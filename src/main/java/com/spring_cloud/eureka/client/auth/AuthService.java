package com.spring_cloud.eureka.client.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class AuthService {

  @Value("${spring.application.name}")
  private String issuer;

  @Value("${service.jwt.access-expiration}")
  private Long accessExpiration;

  private final SecretKey secretKey;

  // 생성자 주입
  public AuthService(
          @Value("${service.jwt.secret-key}")
          String secretKey
  ) {
    this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
  }

  // accessToken 만들기
  public String createAccessToken(String user_id){
    return Jwts.builder()
            .claim("user_id", user_id)
            .claim("role","ADMIN") // 권한
            .issuer(issuer) // 토큰 발급자
            .issuedAt(new Date(System.currentTimeMillis())) // 발행 날짜
            .expiration(new Date(System.currentTimeMillis() + accessExpiration)) // 만료 날짜
            .signWith(secretKey, SignatureAlgorithm.HS512) // 알고리즘 서명
            .compact();
  }
}
