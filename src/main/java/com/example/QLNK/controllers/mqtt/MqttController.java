package com.example.QLNK.controllers.mqtt;

import com.example.QLNK.response.ResponseObject;
import com.example.QLNK.services.mqtt.MqttService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.integration.support.MessageBuilder;
import org.springframework.messaging.MessageChannel;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mqtt")
public class MqttController {

    private final MqttService mqttService;

    @PostMapping("/connect")
    public ResponseEntity<?> connect(Authentication authentication) {
        mqttService.connectUser(authentication);
        return ResponseEntity.status(HttpStatus.OK).body(ResponseObject.builder()
                .status(HttpStatus.OK)
                .message("Subscribe to all topic successfully")
                .data(null)
                .build());
    }
}
