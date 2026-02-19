package com.suraj.hbn.v3.dto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "full_time_employees")
@NoArgsConstructor
@Setter
@Getter
public class FullTimeEmployee extends Employee {
    private int annualLeaves;
    private String benefits; // health, dental, etc
}