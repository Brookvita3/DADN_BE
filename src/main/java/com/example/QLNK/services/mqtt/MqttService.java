package com.example.QLNK.services.mqtt;

import com.example.QLNK.exception.DataNotFoundException;
import com.example.QLNK.model.user.Group;
import com.example.QLNK.model.user.User;
import com.example.QLNK.services.adafruit.AdafruitService;
import com.example.QLNK.services.auth.AuthService;
import com.example.QLNK.services.websocket.WebSocketService;
import lombok.RequiredArgsConstructor;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.integration.channel.PublishSubscribeChannel;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.context.IntegrationFlowContext;
import org.springframework.integration.mqtt.core.DefaultMqttPahoClientFactory;
import org.springframework.integration.mqtt.core.MqttPahoClientFactory;
import org.springframework.integration.mqtt.inbound.MqttPahoMessageDrivenChannelAdapter;
import org.springframework.integration.mqtt.support.DefaultPahoMessageConverter;
import org.springframework.messaging.MessageChannel;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class MqttService {

    private final WebSocketService webSocketService;

    private final Map<String, MqttPahoMessageDrivenChannelAdapter> userClients = new ConcurrentHashMap<>();
    private final Map<String, MessageChannel> userChannels = new ConcurrentHashMap<>();
    private final Map<String, IntegrationFlowContext.IntegrationFlowRegistration> userFlows = new ConcurrentHashMap<>();
    private final IntegrationFlowContext integrationFlowContext;
    private final AuthService authService;
    private final AdafruitService adafruitService;

    @Value("${mqtt.broker.url}")
    private String adaUrl;

//    private MessageChannel getUserChannel(String username) {
//        return userChannels.computeIfAbsent(username, k -> new PublishSubscribeChannel());
//    }

    private MessageChannel getUserChannel(String username) {
        return userChannels.computeIfAbsent(username, k -> {
            PublishSubscribeChannel channel = new PublishSubscribeChannel();
            channel.subscribe(message -> {
                try {
                    String topic = message.getHeaders().get("mqtt_receivedTopic").toString();
                    String payload = message.getPayload().toString();
                    System.out.println("📥 Nhận từ topic: " + topic + " | Payload: " + payload);
                } catch (Exception e) {
                    System.err.println("🚨 Lỗi khi xử lý message: " + e.getMessage());
                    e.printStackTrace();
                }
            });
            return channel;
        });
    }



    private MqttConnectOptions mqttConnectOptions(String username, String apiKey) {
        MqttConnectOptions mqttConnectOptions = new MqttConnectOptions();
        mqttConnectOptions.setServerURIs(new String[]{adaUrl});
        mqttConnectOptions.setUserName(username);
        mqttConnectOptions.setPassword(apiKey.toCharArray());
        return mqttConnectOptions;
    }

    private DefaultMqttPahoClientFactory mqttPahoClientFactory(MqttConnectOptions options) {
        DefaultMqttPahoClientFactory factory = new DefaultMqttPahoClientFactory();
        factory.setConnectionOptions(options);
        return factory;
    }

    private MqttPahoMessageDrivenChannelAdapter adapter(String username, MqttPahoClientFactory factory) {
        List<String> feedKeys = adafruitService.getFeedKeys(username); // Lấy danh sách feed key từ API

        String[] topics = feedKeys.stream()
                .map(key -> username + "/feeds/" + key + "/json")
                .toArray(String[]::new);
        String clientId = "mqtt-client-" + username;
        System.out.println("📡 Subscribing to topics: " + Arrays.toString(topics) + " with clientId: " + clientId);

        MqttPahoMessageDrivenChannelAdapter adapter =
                new MqttPahoMessageDrivenChannelAdapter(clientId, factory, topics);

        adapter.setConverter(new DefaultPahoMessageConverter());
        adapter.setQos(1);
        adapter.setOutputChannel(getUserChannel(username));

        return adapter;
    }

    private IntegrationFlow integrationFlow(MessageChannel channel, String username) {
        System.out.println("🔄 Tạo IntegrationFlow cho user: " + username);
        return IntegrationFlow.from(channel)
                .handle(message -> {
                    String payload = message.getPayload().toString();
                    System.out.println("💡 [IntegrationFlow] Nhận dữ liệu MQTT: " + payload);
                    webSocketService.sendMessageToUser(username, payload);
                })
                .get();
    }


    public void connectUser(Authentication authentication) {

        User user = authService.getAuthenticatedUser(authentication);
        String username = user.getUsername();
        String apiKey = user.getApikey();

        if (userClients.containsKey(username) || userFlows.containsKey(username)) {
            System.out.println("⚠️ Adapter đã tồn tại cho user: " + username);
            return;
        }

        MqttConnectOptions options = mqttConnectOptions(username, apiKey);

        DefaultMqttPahoClientFactory factory = mqttPahoClientFactory(options);

        MqttPahoMessageDrivenChannelAdapter adapter = adapter(username, factory);

        IntegrationFlow flow = integrationFlow(adapter.getOutputChannel(), username);


        userChannels.put(username, adapter.getOutputChannel());

        userClients.put(username, adapter);

        IntegrationFlowContext.IntegrationFlowRegistration registration = integrationFlowContext.registration(flow).register();
        userFlows.put(username, registration);

        adapter.start();
    }

    public void disconnectUser(String username) {
        MqttPahoMessageDrivenChannelAdapter adapter = userClients.remove(username);
        if (adapter != null) {
            adapter.stop();
            System.out.println("🚫 Disconnected MQTT client for user: " + username);
        }

        IntegrationFlowContext.IntegrationFlowRegistration registration = userFlows.remove(username);
        if (registration != null) {
            integrationFlowContext.remove(registration.getId());
        }

        userFlows.remove(username);
        userChannels.remove(username);
    }

}
