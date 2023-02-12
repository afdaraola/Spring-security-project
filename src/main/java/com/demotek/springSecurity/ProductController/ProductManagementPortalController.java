package com.demotek.springSecurity.ProductController;

import com.demotek.springSecurity.dto.Product;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api")
public class ProductManagementPortalController {

    private final List<Product> productList = Arrays.asList(
            new Product(1L, "Low", "low interest product", "simple"),
            new Product(2L, "Medium", "second  tier interest", "Medium"),
            new Product(3L, "High", "higher rate", "Higher")
    );


    @GetMapping()
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Product> getAllProduct(){
        System.out.println("getAllProduct");
        return productList;
    }

    @PostMapping("/create")
    @PreAuthorize("hasAuthority('student:write')")
    public Product CreateNewProduct(@RequestBody Product product){
        System.out.println("CreateNewProduct");
        System.out.println(product);
        return product;
    }

    @PutMapping("/update/{productId}")
    @PreAuthorize("hasAuthority('student:write')")
    public Product updateProduct(@PathVariable("productId") Long productId, @RequestBody Product product){
        System.out.println("update");
        System.out.println(product);

        return product;
    }

    @DeleteMapping("/delete/{productId}")
    @PreAuthorize("hasAuthority('student:write')")
    public String deleteProduct(@PathVariable("productId") Long productId){
        System.out.println("delete");
        System.out.println("Deleted successfully");

        return "Deleted Successfully";
    }
}
