package co.nz.csoft.bookonegateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class BookoneGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(BookoneGatewayApplication.class, args);
	}

}
