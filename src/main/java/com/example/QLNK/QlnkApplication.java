package com.example.QLNK;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class QlnkApplication {

	public static void main(String[] args) {
		SpringApplication.run(QlnkApplication.class, args);
	}

}
