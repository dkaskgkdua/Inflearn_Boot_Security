package io.security.basicsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {

    @GetMapping(value="/")
    public String home() throws Exception {
        return "home";
    }

    @GetMapping("/test")
    @ResponseBody
    public String test() throws Exception {
        return "test";
    }

}