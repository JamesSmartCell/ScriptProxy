package com.stl.smartlayer;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SmartLayer2Application {

    public static void main(String[] args) {
        SpringApplication.run(SmartLayer2Application.class, args);
    }

    @Bean
    CommandLineRunner init() {
        return (args) -> {

        };
    }

}
