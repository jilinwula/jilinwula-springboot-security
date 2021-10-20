package com.jilinwula.security.controller;

import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;

@Controller
public class LoginController {

    @GetMapping("/asdf")
    public String error(HttpServletRequest request, Model model) {
        AuthenticationException exception = (AuthenticationException) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        String error;
        if (exception instanceof UsernameNotFoundException || exception instanceof BadCredentialsException) {
            error = "用户名或密码错误";
        } else if (exception instanceof DisabledException) {
            error = "账户已禁用";
        } else if (exception instanceof LockedException) {
            error = "账户已锁定";
        } else if (exception instanceof AccountExpiredException) {
            error = "账户已过期";
        } else if (exception instanceof CredentialsExpiredException) {
            error = "证书已过期";
        } else {
            error = "登录失败";
        }
        model.addAttribute("qq", error);
        return "test";
    }

    @GetMapping("/test")
    public String test() {
        return "test";
    }
}
