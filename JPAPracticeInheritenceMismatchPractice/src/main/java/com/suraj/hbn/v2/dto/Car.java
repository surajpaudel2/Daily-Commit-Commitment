package com.suraj.hbn.v2.dto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "cars")
@NoArgsConstructor
@Setter
@Getter
public class Car extends Vehicle {
    private int numberOfDoors;
    private String bodyType; // sedan, SUV, hatchback
}