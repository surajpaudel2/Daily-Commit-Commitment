package com.suraj.hbn.v1.dto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Entity
@DiscriminatorValue("ADMIN")
@Setter
@Getter
@RequiredArgsConstructor
public class Admin extends User {
    private String department;
    private int accessLevel;
}
