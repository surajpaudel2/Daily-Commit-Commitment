package com.suraj.hbn.v1.dto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Entity
@DiscriminatorValue("CUSTOMER")
@Setter
@Getter
@RequiredArgsConstructor
public class Customer extends User {
    private String shippingAddress;
    private String loyaltyTier;
}
