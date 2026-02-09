package com.suraj.sendingmailfromjava.controllers;

import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SendMail {

    @Autowired
    private  JavaMailSender mailSender;

    @PostMapping("/send")
    public ResponseEntity<String> sendMail(@RequestParam String to, @RequestParam String subject, @RequestParam String body) {
        // 2. Create the Envelope (The Object)
        SimpleMailMessage message = new SimpleMailMessage();

        // 3. Fill in the details (The Content)
        message.setFrom("me@gmail.com");
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);

        // 4. The Action (Triggering the Protocol)
        mailSender.send(message);

        return  ResponseEntity.ok("Mail Sent Successfully");
    }

}
