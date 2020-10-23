package br.com.gobsio.multisession.controllers;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.session.Session;
// import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SignInController {

    @GetMapping("/login")
    public String loginPage(Model model, Principal principal, HttpSession session, HttpServletRequest request,
            HttpServletResponse response) throws Exception {

        String formAction = "/login";

        String queryString = request.getQueryString();

        if (queryString != null) {
            formAction = "/login?" + queryString;
        }

        model.addAttribute("formAction", formAction);

        return "login.html";
    }

}