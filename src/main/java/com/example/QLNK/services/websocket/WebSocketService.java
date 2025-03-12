package com.example.QLNK.services.websocket;

import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class WebSocketService {
    private final SimpMessagingTemplate messagingTemplate;

    public void sendMessageToUser(String username, String data) {
        System.out.println("📡 Gửi WebSocket tới: " + username + " | Nội dung: " + data);
        messagingTemplate.convertAndSend("/topic/" + username, data);
    }
}
