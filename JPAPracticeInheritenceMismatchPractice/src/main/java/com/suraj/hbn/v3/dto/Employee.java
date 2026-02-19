package com.suraj.hbn.v3.dto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@Setter
@Getter
@NoArgsConstructor
public abstract class Employee {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE) // TABLE_PER_CLASS requires SEQUENCE, not IDENTITY
    private Long id;
    private String name;
    private String email;
    private double baseSalary;
}