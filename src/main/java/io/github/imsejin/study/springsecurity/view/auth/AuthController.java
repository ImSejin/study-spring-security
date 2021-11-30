package io.github.imsejin.study.springsecurity.view.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("auth")
class AuthController {

    @GetMapping
    Object login() {
        return "authentication";
    }

}
