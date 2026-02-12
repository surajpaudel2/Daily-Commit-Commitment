package com.suraj.securitydd.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping
    public String getAdminDetails() {
        System.out.println("AdminController.getAdminDetails()");
        return "AdminController.getAdminDetails()";
    }

    @PostMapping
    public String postAdminDetails() {
        System.out.println("AdminController.postAdminDetails()");
        return "AdminController.postAdminDetails()";
    }

    @DeleteMapping
    public String deleteAdminDetails() {
        System.out.println("AdminController.deleteAdminDetails()");
        return "AdminController.deleteAdminDetails()";
    }

    @PutMapping
    public String putAdminDetails() {
        System.out.println("AdminController.putAdminDetails()");
        return "AdminController.putAdminDetails()";
    }

}
