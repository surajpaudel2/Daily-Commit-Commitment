package com.suraj.hbn.associationmismatchdemo;

import com.suraj.hbn.associationmismatchdemo.v1_one_to_one.dto.Address;
import com.suraj.hbn.associationmismatchdemo.v1_one_to_one.dto.Passport;
import com.suraj.hbn.associationmismatchdemo.v1_one_to_one.dto.Person;
import com.suraj.hbn.associationmismatchdemo.v1_one_to_one.repository.PersonRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Optional;

@SpringBootApplication
@RequiredArgsConstructor
public class AssociationMismatchDemoApplication {


    private final PersonRepository personRepository;

    public static void main(String[] args) {
        SpringApplication.run(AssociationMismatchDemoApplication.class, args);
    }

    @PostConstruct
    public void demo() {
//        Person person = new Person();
//        person.setName("Suraj");
//        person.setEmail("suraj@gmail.com");
//
//        Passport passport = new Passport();
//        passport.setPassportNumber("AU123456");
//        passport.setCountry("Australia");
//        passport.setExpiryDate("2030-01-01");
//
//        Address address = new Address();
//        address.setStreet("123 George Street");
//        address.setCity("Sydney");
//        address.setCountry("Australia");
//        address.setZipCode("2000");
//
//        person.setPassport(passport);
//        person.setAddress(address);
//
//        personRepository.save(person);

        Optional<Person> person = personRepository.findById(new Long(1));
        person.ifPresent(pson -> {
            System.out.println(pson.getAddress());
//            pson.setAddress(null);
            pson.setPassport(null);
            personRepository.save(pson);
        });
    }

}
