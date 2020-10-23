package br.com.gobsio.multisession.config.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
// import org.springframework.session.Session;
// import org.springframework.session.SessionRepository;
// import org.springframework.session.web.http.HttpSessionManager;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

// @Component
// @Order(1)
public class UserAccountsFilter {// implements Filter {

    // private final Logger LOG = LoggerFactory.getLogger(UserAccountsFilter.class);

    // public void init(FilterConfig filterConfig) throws ServletException {
    // }

    // @SuppressWarnings("unchecked")
    // public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    //         throws IOException, ServletException {
    //     HttpServletRequest httpRequest = (HttpServletRequest) request;
    //     HttpServletResponse httpReponse = (HttpServletResponse) response;

    //     // tag::HttpSessionManager[]
    //     HttpSessionManager sessionManager = (HttpSessionManager) httpRequest
    //             .getAttribute(HttpSessionManager.class.getName());

    //     // end::HttpSessionManager[]
    //     SessionRepository<Session> repo = (SessionRepository<Session>) httpRequest
    //             .getAttribute(SessionRepository.class.getName());

    //     String currentSessionAlias = sessionManager.getCurrentSessionAlias(httpRequest);
    //     Map<String, String> sessionIds = sessionManager.getSessionIds(httpRequest);
    //     String unauthenticatedAlias = null;

    //     this.info(" >>>> ");
    //     this.info("" + httpRequest.getRequestURI());
    //     this.info("" + httpRequest.getHeader("x-oauth-user"));
    //     this.info("_____1Current User Alias:  " + currentSessionAlias);

    //     String contextPath = httpRequest.getContextPath();
    //     List<Account> accounts = new ArrayList<Account>();
    //     Account currentAccount = null;

    //     for (Map.Entry<String, String> entry : sessionIds.entrySet()) {
    //         String alias = entry.getKey();
    //         String sessionId = entry.getValue();

    //         this.info("alias ......:  " + alias);
    //         this.info("sessionId ..:  " + sessionId);

    //         Session session = repo.getSession(sessionId);
    //         if (session == null) {
    //             continue;
    //         }

    //         SecurityContext sc = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");

    //         if (sc != null) {
    //             Authentication authentication = sc.getAuthentication();
    //             String username = authentication.getName();

    //             if (username == null) {
    //                 this.info("unauthenticatedAlias ..:  " + alias);
    //                 unauthenticatedAlias = alias;
    //                 continue;
    //             }

    //             String logoutUrl = sessionManager.encodeURL("./logout", alias);
    //             String switchAccountUrl = sessionManager.encodeURL("./", alias);
    //             Account account = new Account(username, logoutUrl, switchAccountUrl);
    //             account.setAuthentication(authentication);
    //             if (currentSessionAlias.equals(alias)) {
    //                 this.info("currentSessionAlias.equals(alias) ..:  " + alias);
    //                 currentAccount = account;
    //             } else {
    //                 this.info("accounts.add(account) ..:  " + alias);
    //                 accounts.add(account);
    //             }
    //         }
    //     }

    //     this.info("");
    //     this.info(" <<<< ");

    //     // tag::addAccountUrl[]
    //     String addAlias = unauthenticatedAlias == null ? // <1>
    //             sessionManager.getNewSessionAlias(httpRequest) : // <2>
    //             unauthenticatedAlias; // <3>
    //     String addAccountUrl = sessionManager.encodeURL(contextPath, addAlias); // <4>
    //     // end::addAccountUrl[]

    //     httpRequest.setAttribute("currentAccount", currentAccount);
    //     httpRequest.setAttribute("addAccountUrl", addAccountUrl);
    //     httpRequest.setAttribute("accounts", accounts);

    //     chain.doFilter(request, response);
    // }

    // public void destroy() {
    // }


    // private void getCurrentUserInfoCookie(HttpServletRequest request, String cookieName) {
    //     WebUtils.getCookie(request, "SSID");
    // }

    // private void info(String s) {
    //     System.out.println(s);
    // }
}