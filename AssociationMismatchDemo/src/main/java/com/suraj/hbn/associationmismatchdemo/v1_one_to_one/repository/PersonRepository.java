package com.suraj.hbn.associationmismatchdemo.v1_one_to_one.repository;

import com.suraj.hbn.associationmismatchdemo.v1_one_to_one.dto.Person;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PersonRepository extends JpaRepository<Person, Long> {
}
