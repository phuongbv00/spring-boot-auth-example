package io.github.censodev.springbootauthexample;

import io.github.censodev.jwtprovider.JwtProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Slf4j
public class SecurityConfig {
    @Value("${auth.secret}")
    private String authSecret;

    @Bean
    public JwtProvider tokenProvider() {
        return JwtProvider.secret(authSecret).build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthFilter<User> filter = new AuthFilter<>(tokenProvider(), User.class);
        return http
                .csrf()
                .disable()
                .cors()
                .and()
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .antMatchers("/api/auth/login", "/api/auth/signup").permitAll()
                        .antMatchers("/api/mfa/**", "/mfa/index.html").permitAll()
                        .anyRequest().authenticated()
                )
                .httpBasic(withDefaults())
                .build();
    }
}
