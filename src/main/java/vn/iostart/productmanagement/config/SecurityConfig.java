package vn.iostart.productmanagement.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;
import vn.iostart.productmanagement.security.CustomUserDetailsService;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    DaoAuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(
                        userDetailsService
                );

        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {

        http
            /*
             * GraphQL và REST API được gọi bằng AJAX.
             */
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    "/graphql",
                    "/api/**"
                )
            )

            .authenticationProvider(
                authenticationProvider()
            )

            .authorizeHttpRequests(authorize -> authorize

                /*
                 * Các đường dẫn công khai.
                 */
            		.requestMatchers(
            			    "/login",
            			    "/register",
            			    "/error",
            			    "/access-denied",
            			    "/favicon.ico",
            			    "/css/**",
            			    "/js/**",
            			    "/images/**",
            			    "/uploads/**"
            			).permitAll()

                /*
                 * ADMIN và USER đều được xem chi tiết sản phẩm.
                 *
                 * Ví dụ:
                 * GET /products/1
                 * GET /products/25
                 */
                .requestMatchers(
                    HttpMethod.GET,
                    "/products/{id:[0-9]+}"
                ).authenticated()

                /*
                 * Chỉ ADMIN được truy cập chức năng quản lý.
                 */
                .requestMatchers(
                    "/products/**",
                    "/categories/**",
                    "/api/**",
                    "/graphiql",
                    "/graphiql/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/v3/api-docs/**"
                ).hasRole("ADMIN")

                /*
                 * Các đường dẫn còn lại yêu cầu đăng nhập.
                 */
                .anyRequest().authenticated()
            )

            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("login")
                .passwordParameter("password")
                .defaultSuccessUrl("/", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )

            .rememberMe(remember -> remember
                .key("product-management-remember-key")
                .tokenValiditySeconds(
                    7 * 24 * 60 * 60
                )
                .userDetailsService(userDetailsService)
            )

            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies(
                    "JSESSIONID",
                    "remember-me"
                )
                .permitAll()
            )

            .exceptionHandling(exception -> exception
                .accessDeniedPage("/access-denied")
            );

        return http.build();
    }
}