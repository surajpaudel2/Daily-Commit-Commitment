package com.suraj.hbn.v3.dto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "contract_employees")
@NoArgsConstructor
@Setter
@Getter
public class ContractEmployee extends Employee {
    private String contractDuration; // "6 months", "1 year"
    private String agency;
}