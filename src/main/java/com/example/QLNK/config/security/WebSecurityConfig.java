package com.example.QLNK.config.security;

import com.example.QLNK.config.jwt.JwtAuthenticationFilter;
import com.example.QLNK.config.jwt.JwtEntryPoint;
import com.example.QLNK.config.jwt.JwtUtils;
import com.example.QLNK.model.user.User;
import com.example.QLNK.repositories.UserRepository;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtEntryPoint jwtEntryPoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers( "/", "/auth/**").permitAll()
                .requestMatchers("/ws/**").permitAll()
                .requestMatchers("/auth/logout", "/auth/refresh-token").authenticated()
                .anyRequest().authenticated()
        );

        http.formLogin(AbstractHttpConfigurer::disable);
        http.csrf(AbstractHttpConfigurer::disable);

        // Nho handle viec failureHandler
        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo.userService(oauth2UserService(userRepository)))
                .failureHandler((request, response, exception) -> {
                    System.out.println("OAuth2 Login Failed: " + exception.getMessage());
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":401, \"message\":\"OAuth2 login failed\", \"error\":\"" + exception.getMessage() + "\"}");
                })
                .successHandler((request, response, authentication) -> {
                    DefaultOAuth2User oAuth2User = (DefaultOAuth2User) authentication.getPrincipal();

                    String email = (String) oAuth2User.getAttributes().get("email");
                    String avatarUrl = (String) oAuth2User.getAttributes().get("picture");
                    User user = userRepository.findByEmail(email).orElseThrow();

                    if (user.getUrlava() == null || user.getUrlava().isEmpty()) {
                        user.setUrlava(avatarUrl);
                        userRepository.save(user);
                    }

                    String role = (user.getUsername() == null || user.getApikey() == null) ? "INCOMPLETE_USER" : "USER";
                    String jwt = jwtUtils.generateAccessTokenWithRole(email, role);

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user, null, Collections.singleton(new SimpleGrantedAuthority(role)));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    response.addCookie(new Cookie("JWT-TOKEN", jwt));
                    response.setContentType("application/json");
                    response.getWriter().write("{\"status\":200, \"message\":\"Login successful\", \"token\":\"" + jwt + "\"}");
                })
        );

        http.exceptionHandling((exception ->
                exception.authenticationEntryPoint(jwtEntryPoint)));
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(UserRepository userRepository ) {
        return userRequest -> {
            OAuth2User oauth2User = new DefaultOAuth2UserService().loadUser(userRequest);

            System.out.println("OAuth2 Attributes: " + oauth2User.getAttributes());

            String email = (String) oauth2User.getAttributes().get("email");
            String urlava = (String) oauth2User.getAttributes().get("picture");

            if (email == null) {
                throw new IllegalArgumentException("Email attribute is missing in OAuth2 response");
            }

            User user = userRepository.findByEmail(email).orElseGet(() -> {
                User newUser = User.builder()
                        .email(email)
                        .urlava(urlava)
                        .username(null)
                        .apikey(null)
                        .build();
                return userRepository.save(newUser);
            });

            return new DefaultOAuth2User(
                    Collections.singleton(new SimpleGrantedAuthority("USER")),
                    oauth2User.getAttributes(),
                    "email"
            );
        };
    }
}
