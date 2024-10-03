package com.example.jwtdemo.config;


import com.example.jwtdemo.service.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
@EnableWebSecurity

/**
 * 安全管理的框架，就是要保護服務、資料等各項資源，不會被任意存取。
 */
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable()) // 停用對於 CSRF 攻擊的保護機制，讓 Postman 工具能順利存取 API
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll()) // 授權規則: 設定為 API 不需通過認證也可存取
                .build();
    }

    @Bean
    public UserDetailsService inMemoryUserDetailsManager() {
        // 測試使用者，帳號為「user1」，密碼為「111」，權限為「學生」與「助理」
        UserDetails user = User
                .withUsername("user1")
                .password("111")
                .authorities("STUDENT", "ASSISTANT")
                .build();
        return new InMemoryUserDetailsManager(List.of(user));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 指定密碼的加密方式
        return NoOpPasswordEncoder.getInstance(); // 不加密
    }

    @Bean
    public JwtService jwtService(
            @Value("${jwt.secret-key}") String secretKeyStr,//密鑰
            @Value("${jwt.valid-seconds}") int validSeconds
    ) {
        return new JwtService(secretKeyStr, validSeconds);
    }
}
