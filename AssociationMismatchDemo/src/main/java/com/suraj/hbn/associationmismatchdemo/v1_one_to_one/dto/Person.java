// Person.java
package com.suraj.hbn.associationmismatchdemo.v1_one_to_one.dto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "persons")
@NoArgsConstructor
@Getter
@Setter
public class Person {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String email;

    @OneToOne(cascade =  CascadeType.ALL, fetch = FetchType.EAGER, optional = true, orphanRemoval = false)
//    @JoinColumn(name = "address_id", nullable = false)
    private Address address;

    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true, optional = false)
//    @JoinColumn(name = "passport_id", nullable = true)
    private Passport passport;
}

// WHAT I AM TRYING TO ACHEIVE
/*
    1. For both passport and addresses I want to modify if person is modified.
    2. For address I want to have it loading early even if the client dosn't request for the address, whereas, for the passport i don't want to load early.
    3. For address I am ok with even if the person is not there address is there but not for the passport.
    4. For address I don't want to delete if the address is set null but for passport exact opposite.

 */