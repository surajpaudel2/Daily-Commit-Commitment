package com.suraj.securitydd.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/public")
@RestController
public class PublicController {

    @GetMapping
    public String publicController() {
        System.out.println("publicController.publicController()");
        return "publicController.publicController()";
    }

    @PostMapping("/post")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String postController() {
        System.out.println("postController.postController()");
        return "postController.postController()";
    }

    @PutMapping
    public String putController() {
        System.out.println("putController.putController()");
        return "putController.putController()";
    }

    @DeleteMapping
    public String deleteController() {
        System.out.println("deleteController.deleteController()");
        return "deleteController.deleteController()";
    }
}
