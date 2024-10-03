package com.example.jwtdemo.controller;


import com.example.jwtdemo.dto.LoginRequest;
import com.example.jwtdemo.service.JwtService;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class MyController {

    private static final String BEARER_PREFIX = "Bearer ";

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtService jwtService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request) {
        UserDetails user = userDetailsService.loadUserByUsername(request.getUsername()); // 查詢使用者
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) { // 比對密碼
            throw new BadCredentialsException("Authentication fails because of incorrect password.");
        }

        //return "帳密正確，回傳 JWT";
        return jwtService.createLoginAccessToken(user);
    }

    @GetMapping("/who-am-i")//當解析 JWT 成功後，可以將 JWT Payload 中的信息存儲在一個 Map<String, Object>
    public Map<String, Object> whoAmI(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization) {
        // 在 request header 攜帶 JWT 時，格式是先以「Bearer」加一個半形空格做為前綴，才加上 JWT。因此後端接收到 header 後，要先排除該前綴，才能進行解析
        // 不知道是不是JWT都是這樣?????
        String jwt = authorization.substring(BEARER_PREFIX.length());
        try {
            return jwtService.parseToken(jwt);//回傳解析好的jwt
        } catch (JwtException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }
}