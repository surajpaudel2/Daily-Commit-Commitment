package com.suraj.hbn.v3.repository;

import com.suraj.hbn.v3.dto.ContractEmployee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ContractEmployeeRepository extends JpaRepository<ContractEmployee, Long> {}