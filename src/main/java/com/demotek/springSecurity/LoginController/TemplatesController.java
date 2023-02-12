package com.demotek.springSecurity.LoginController;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplatesController {


    @GetMapping("login")
    public String getLoginView(){
        return "login";
    }

    @GetMapping("products")
    public String getProductView(){
        return "products";
    }
}
