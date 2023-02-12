package com.demotek.springSecurity.ProductController;

import com.demotek.springSecurity.dto.Product;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/product/api")
public class ProdController {

    private final List<Product> productList = Arrays.asList(
            new Product(1L, "Low", "low interest product", "simple"),
            new Product(2L, "Medium", "second  tier interest", "Medium"),
            new Product(3L, "High", "higher rate", "Higher")
    );

    @GetMapping("{productId}")
    public Product getProduct(@PathVariable(value = "productId") Long productId) {

        return productList.stream().filter(product -> productId.equals(product.getId()))
                .findFirst().orElseThrow(() -> new IllegalAccessError("The product id " + productId + " does not exists"));


    }
}
