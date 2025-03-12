package com.example.QLNK.config.websocket;

import com.example.QLNK.config.jwt.JwtUtils;
import com.example.QLNK.services.users.CustomUserDetailService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtWebSocketInterceptor implements HandshakeInterceptor {
    private final JwtUtils jwtUtils;
    private final CustomUserDetailService customUserDetailService;

    @Override
    public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Map<String, Object> attributes) {

        System.out.println("⚡ WebSocket Interceptor TRIGGERED!");
        if (request instanceof ServletServerHttpRequest) {
            HttpServletRequest httpRequest = ((ServletServerHttpRequest) request).getServletRequest();
            String token = httpRequest.getParameter("token");
            System.out.println("🔑 WebSocket Token: " + token);
            if (jwtUtils.validateToken(token)) {
                String email = jwtUtils.extractEmail(token);
                UserDetails userDetails = customUserDetailService.loadUserByUsername(email);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                attributes.put("user", authentication.getPrincipal()); // Lưu user vào WebSocket session
                System.out.println("✅ Xác thực WebSocket thành công!");
                return true;
            }
        }
        return false;
    }

    @Override
    public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Exception exception) {
    }
}
