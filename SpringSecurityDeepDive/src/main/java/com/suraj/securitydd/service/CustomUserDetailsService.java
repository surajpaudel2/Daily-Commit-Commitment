package com.suraj.securitydd.service;

import com.suraj.securitydd.entity.CustomUser;
import com.suraj.securitydd.entity.Role;
import com.suraj.securitydd.entity.Users;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = new Users();
        user.setUsername(username);
        user.setRole(Role.ADMIN);
        user.setPhone("123456789");

        return new CustomUser(user);
    }
}
