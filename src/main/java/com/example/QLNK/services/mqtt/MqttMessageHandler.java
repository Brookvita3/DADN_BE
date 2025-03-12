package com.example.QLNK.services.mqtt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

@Component
public class MqttMessageHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

}
