package com.example.QLNK.services.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    private final JavaMailSender javaMailSender;
    private final String emailUsername;

    public EmailService(JavaMailSender javaMailSender, @Value("${EMAIL_USERNAME}") String emailUsername) {
        this.javaMailSender = javaMailSender;
        this.emailUsername = emailUsername;
    }

    @Async
    public void sendMailToUser(String to, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(emailUsername);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        javaMailSender.send(message);
    }

}
