package com.emsi.billingservice.feign;

import com.emsi.billingservice.model.Customer;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.hateoas.PagedModel;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "CUSTOMER-SERVICE")
public interface CustomerRestClient {
    @GetMapping("/customers/{id}")
    Customer getCustomerById(@RequestHeader("Authorization") String token, @PathVariable Long id);


    @GetMapping("/customers")
    PagedModel<Customer> getPageCustomers(
            @RequestHeader("Authorization") String token,
            @RequestParam(value="page") int page,
            @RequestParam(value="size") int size
    );
}
