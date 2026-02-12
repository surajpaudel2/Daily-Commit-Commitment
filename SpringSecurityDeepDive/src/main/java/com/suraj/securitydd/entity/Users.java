package com.suraj.securitydd.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Users {

    private String username;
    private String password;
    private Role role;
    private String email;
    private String phone;
    private String address;

}
