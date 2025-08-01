package br.com.travelex.cognito;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "br.com.travelex.cognito")
public class CognitoApplication {

	public static void main(String[] args) {
		SpringApplication.run(CognitoApplication.class, args);
		
	}

}
