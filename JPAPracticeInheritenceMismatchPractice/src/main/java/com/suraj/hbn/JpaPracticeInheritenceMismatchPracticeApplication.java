package com.suraj.hbn;

import com.suraj.hbn.v1.dto.Admin;
import com.suraj.hbn.v1.dto.Customer;
import com.suraj.hbn.v1.repository.AdminRepository;
import com.suraj.hbn.v1.repository.CustomerRepository;
import com.suraj.hbn.v2.dto.Car;
import com.suraj.hbn.v2.dto.Motorcycle;
import com.suraj.hbn.v2.repository.CarRepository;
import com.suraj.hbn.v2.repository.MotorcycleRepository;
import com.suraj.hbn.v3.dto.ContractEmployee;
import com.suraj.hbn.v3.dto.FullTimeEmployee;
import com.suraj.hbn.v3.repository.ContractEmployeeRepository;
import com.suraj.hbn.v3.repository.FullTimeEmployeeRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JpaPracticeInheritenceMismatchPracticeApplication {

    // --- v1 repositories ---
    @Autowired AdminRepository adminRepository;
    @Autowired CustomerRepository customerRepository;

    // --- v2 repositories ---
    @Autowired CarRepository carRepository;
    @Autowired MotorcycleRepository motorcycleRepository;

    // --- v3 repositories ---
    @Autowired FullTimeEmployeeRepository fullTimeEmployeeRepository;
    @Autowired ContractEmployeeRepository contractEmployeeRepository;

    public static void main(String[] args) {
        SpringApplication.run(JpaPracticeInheritenceMismatchPracticeApplication.class, args);
    }

    @PostConstruct
    public void run() {
        // seedV1();
        // seedV2();
        seedV3();
    }

    // ==================================================================================
    // V1 — SINGLE_TABLE inheritance
    // All subclasses (Admin, Customer) share ONE table "users"
    // A discriminator column "user_type" tells JPA which subtype each row belongs to
    // Pro: simple, fast queries — no joins needed
    // Con: nullable columns for every subtype's fields (can't enforce NOT NULL on subclass fields)
    // ==================================================================================
    private void seedV1() {
        Admin admin = new Admin();
        admin.setName("Suraj");
        admin.setEmail("suraj@company.com");
        admin.setDepartment("Engineering");
        admin.setAccessLevel(5);

        Customer customer = new Customer();
        customer.setName("John");
        customer.setEmail("john@gmail.com");
        customer.setShippingAddress("Rockdale");
        customer.setLoyaltyTier("1122A");

        adminRepository.save(admin);
        customerRepository.save(customer);
    }

    // ==================================================================================
    // V2 — JOINED inheritance
    // Parent table "vehicles" holds common fields, each subclass (Car, Motorcycle)
    // has its OWN table with only its extra fields, joined on the primary key
    // Pro: normalized, no nulls, clean schema
    // Con: every query costs a JOIN between parent and child table
    // ==================================================================================
    private void seedV2() {
        Car car = new Car();
        car.setBrand("Toyota");
        car.setYear(2022);
        car.setPrice(35000.00);
        car.setNumberOfDoors(4);
        car.setBodyType("SUV");

        Motorcycle moto = new Motorcycle();
        moto.setBrand("Harley-Davidson");
        moto.setYear(2021);
        moto.setPrice(20000.00);
        moto.setMotorcycleType("cruiser");
        moto.setHasSidecar(false);

        carRepository.save(car);
        motorcycleRepository.save(moto);
    }

    // ==================================================================================
    // V3 — TABLE_PER_CLASS inheritance
    // NO shared parent table — each concrete subclass (FullTimeEmployee, ContractEmployee)
    // gets its OWN complete table including ALL parent fields duplicated
    // Note: requires GenerationType.SEQUENCE (not IDENTITY) to keep IDs unique across tables
    // Pro: no joins needed for subtype queries, clean per-type tables
    // Con: parent fields duplicated across tables, polymorphic queries use UNION (slow)
    // ==================================================================================
    private void seedV3() {
        FullTimeEmployee fte = new FullTimeEmployee();
        fte.setName("Alice");
        fte.setEmail("alice@company.com");
        fte.setBaseSalary(90000.00);
        fte.setAnnualLeaves(20);
        fte.setBenefits("Health, Dental");

        ContractEmployee ce = new ContractEmployee();
        ce.setName("Bob");
        ce.setEmail("bob@agency.com");
        ce.setBaseSalary(75000.00);
        ce.setContractDuration("6 months");
        ce.setAgency("TechStaff Pty Ltd");

        fullTimeEmployeeRepository.save(fte);
        contractEmployeeRepository.save(ce);
    }
}