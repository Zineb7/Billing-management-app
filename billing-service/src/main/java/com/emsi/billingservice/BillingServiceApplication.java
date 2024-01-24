package com.emsi.billingservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class BillingServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(BillingServiceApplication.class, args);
	}
	/*@Bean
	CommandLineRunner start(
			BillRepository billRepository,
			ProductItemRepository productItemRepository,
			CustomerRestClient customerRestClient,
			ProductRestClient productRestClient,
			RepositoryRestConfiguration repositoryRestConfiguration
	) {
		return args -> {
			repositoryRestConfiguration.exposeIdsFor(Bill.class);
			PagedModel<Product> products=productRestClient.getPageProducts(0,10);
			for (int i = 1; i < 4; i++) {
				Customer customer=customerRestClient.getCustomerById((long) i);
				Bill b=billRepository.save(
					new Bill(
						null,
						new Date(),
						null,
						customer.getId(),
						null
					)
				);
				products.forEach(
					p->{
						ProductItem pi= new ProductItem(
							null,
							p.getQuantity(),
							p.getId(),
							p.getPrice(),
							b,
							null
						);
						productItemRepository.save(pi);
					}
				);
			}
		};
	}*/
}
