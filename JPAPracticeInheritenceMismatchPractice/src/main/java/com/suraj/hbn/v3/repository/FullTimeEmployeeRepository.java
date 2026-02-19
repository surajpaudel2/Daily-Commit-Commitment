package com.suraj.hbn.v3.repository;

import com.suraj.hbn.v3.dto.FullTimeEmployee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FullTimeEmployeeRepository extends JpaRepository<FullTimeEmployee, Long> {}