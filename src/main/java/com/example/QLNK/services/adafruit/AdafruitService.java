package com.example.QLNK.services.adafruit;

import com.example.QLNK.model.user.Feed;
import com.example.QLNK.model.user.Group;
import com.example.QLNK.model.user.User;
import com.example.QLNK.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AdafruitService {
    private final UserRepository userRepository;

    @Value("${http.adafruit.url}")
    private String httpUrl;

    private final RestTemplate restTemplate;

    public List<Group> getGroups(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-AIO-Key", user.getApikey());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        String url = httpUrl + "/" + user.getUsername() + "/groups";
        ResponseEntity<Group[]> response = restTemplate.exchange(
                url, HttpMethod.GET, request, Group[].class);

        return Optional.ofNullable(response.getBody())
                .map(Arrays::asList)
                .orElse(Collections.emptyList());
    }

    public List<String> getFeedKeys(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-AIO-Key", user.getApikey());

        HttpEntity<Void> request = new HttpEntity<>(headers);
        String url = httpUrl + "/" + user.getUsername() + "/groups";

        ResponseEntity<Group[]> response = restTemplate.exchange(
                url, HttpMethod.GET, request, Group[].class);

        return Optional.ofNullable(response.getBody())
                .stream()
                .flatMap(Arrays::stream)
                .flatMap(group -> group.getFeeds().stream().map(Feed::getKey)) // Lấy key từ mỗi feed
                .toList();
    }



}
