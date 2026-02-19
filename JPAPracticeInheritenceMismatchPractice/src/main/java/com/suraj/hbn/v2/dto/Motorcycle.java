package com.suraj.hbn.v2.dto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "motorcycles")
@NoArgsConstructor
@Setter
@Getter
public class Motorcycle extends Vehicle {
    private String motorcycleType; // sport, cruiser, touring
    private boolean hasSidecar;
}