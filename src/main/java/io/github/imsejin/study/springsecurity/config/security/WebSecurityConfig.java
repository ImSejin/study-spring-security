package io.github.imsejin.study.springsecurity.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * WebSecurityConfig
 *
 * @see AnonymousAuthenticationFilter
 * @see AnonymousAuthenticationToken
 */
@EnableWebSecurity
@RequiredArgsConstructor
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Authentication(인증)
        // All requests must be authenticated.
        http.authorizeRequests().anyRequest().authenticated();

        // Authorization(인가)
        login(http);

        logout(http);
        rememberMe(http);
        manageSession(http);
    }

    /**
     * Login Form Flow
     *
     * <ol>
     *     <li>Receive request.</li>
     *     <li>{@link UsernamePasswordAuthenticationFilter} checks if request URL matches.</li>
     *     <li>If {@link AntPathRequestMatcher} returns {@code true}, pass the next step,
     *         else execute {@code chain.doFilter}.</li>
     *     <li>Pass a {@link Authentication} with username and password.</li>
     *     <li>{@link AuthenticationManager} delegates validation to {@link AuthenticationProvider}.</li>
     *     <li>{@link AuthenticationProvider} validates the given user information.</li>
     *     <li>If authentication succeed, return a {@link Authentication} with user and authorities,
     *         else throw {@link AuthenticationException}.</li>
     *     <li>{@link Authentication} is stored in {@link SecurityContext}.</li>
     *     <li>Invoke {@link AuthenticationSuccessHandler}</li>
     * </ol>
     *
     * @see UsernamePasswordAuthenticationFilter
     */
    private static void login(HttpSecurity http) throws Exception {
        http.formLogin()
//                .loginPage("/auth")                   // Request URL to go to custom login page(default: /login)
                .defaultSuccessUrl("/home")           // Page to arrive after login succeed.
                .failureUrl("/login")                 // Page to arrive after login failed.
                .usernameParameter("id")              // Attribute 'name' in input tag.
                .passwordParameter("pw")              // Attribute 'name' in input tag.
                .loginProcessingUrl("/login-process") // Attribute 'action' in form tag.
                .successHandler(new CustomAuthenticationSuccessHandler())
                .failureHandler(new CustomAuthenticationFailureHandler())
                // Request URL for login page must be passed without authentication.
                // If not, you go to infinite redirect loop.
                .permitAll();
    }

    /**
     * Logout Flow
     *
     * <ol>
     *     <li>Receive request.</li>
     *     <li>{@link LogoutFilter} checks if request URL matches.</li>
     *     <li>If {@link AntPathRequestMatcher} returns {@code true}, pass the next step,
     *         else execute {@code chain.doFilter}.</li>
     *     <li>Get a {@link Authentication} from {@link SecurityContext}.</li>
     *     <li>Pass it to {@link SecurityContextLogoutHandler}.</li>
     *     <li>Invalidate session, delete cookies and invoke {@link SecurityContextHolder#clearContext()}.</li>
     *     <li>Delegate to {@link SimpleUrlLogoutSuccessHandler}.</li>
     *     <li>Redirect to login page.</li>
     * </ol>
     *
     * @see LogoutFilter
     */
    private static void logout(HttpSecurity http) throws Exception {
        http.logout()
//                .logoutUrl("/") // Request URL to go to custom logout page(default: POST /logout)
                .logoutSuccessUrl("/auth")
                .addLogoutHandler((request, response, authentication) -> {
                    System.out.printf("logout-1: '%s'%n", authentication.getName());
                    request.getSession().invalidate();
                })
                .logoutSuccessHandler((request, response, authentication) -> {
                    System.out.printf("Good bye, '%s'!%n", authentication.getName());
                    response.sendRedirect("/login");
                })
                .deleteCookies("remember-me");
    }

    /**
     * Remember-me Flow
     * (Sustain authenticated state and auto-login)
     *
     * <ol>
     *     <li>When {@link Authentication} in {@link SecurityContext} is null and HTTP request
     *         has cookie 'remember-me', execute {@link RememberMeAuthenticationFilter}.</li>
     *     <li>Delegate the job to {@link RememberMeServices}.</li>
     *     <li>Extract the token from cookies.</li>
     *     <li>If the token exists, validate the decoded token,
     *         else execute {@code chain.doFilter}(pass the next filter).</li>
     *     <li>When token is invalid or user account doesn't exist, throw exception.</li>
     *     <li>If pass all the validations, create new a {@link Authentication}.</li>
     *     <li>Pass it to {@link AuthenticationManager}.</li>
     * </ol>
     *
     * @see RememberMeAuthenticationFilter
     */
    private void rememberMe(HttpSecurity http) throws Exception {
        http.rememberMe()
                .rememberMeParameter("rememberMe") // default: remember-me
                .tokenValiditySeconds(3600)        // default: 14 days
                .alwaysRemember(false)
                .userDetailsService(userDetailsService);
    }

    /**
     * Session Management
     *
     * @see SessionManagementFilter
     * @see ConcurrentSessionFilter
     */
    private static void manageSession(HttpSecurity http) throws Exception {
        // Concurrent Session Management
        http.sessionManagement()
                .invalidSessionUrl("/invalid")
                .maximumSessions(1) // If -1, allow infinite concurrent session login.
                // If true, prevent a user from logging in and sustain the previous session.
                // If false, allow a user to login and invalidate the previous session.
                .maxSessionsPreventsLogin(false)
                .expiredUrl("/expired");

        // Protect against session fixation attack.
        http.sessionManagement()
                .sessionFixation()
                .changeSessionId();

        // Session creation policy.
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
    }

    /**
     * Custom authentication success handler
     *
     * @see <a href="https://stackoverflow.com/questions/28103852/spring-boot-session-timeout">
     * Spring Boot Session Timeout</a>
     */
    private static class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
        private static final int SESSION_TIMEOUT = (int) TimeUnit.SECONDS.toSeconds(60);

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authentication) throws IOException {
            request.getSession().setMaxInactiveInterval(SESSION_TIMEOUT);
            System.out.printf("Welcome-1, '%s'!%n", authentication.getName());
            response.sendRedirect("/home");
        }
    }

    private static class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException exception) throws IOException {
            System.out.printf("Failed to login: '%s'%n", exception.getMessage());
            response.sendRedirect("/");
        }
    }

}
