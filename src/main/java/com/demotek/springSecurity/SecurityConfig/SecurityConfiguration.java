package com.demotek.springSecurity.SecurityConfig;

import com.demotek.springSecurity.Auth.ApplicationUserService;
import com.demotek.springSecurity.Jwt.JwtConfig;
import com.demotek.springSecurity.Jwt.JwtTokenVerifier;
import com.demotek.springSecurity.Jwt.JwtUserNameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;


import javax.crypto.SecretKey;

import static com.demotek.springSecurity.SecurityConfig.ApplicationUserRoles.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;


    public SecurityConfiguration(PasswordEncoder passwordEncoder,
                                 ApplicationUserService applicationUserService,
                                 JwtConfig jwtConfig,
                                 SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUserNameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig,secretKey))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig,secretKey) ,JwtUserNameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/product/**").hasRole(USER.name())
                .anyRequest()
                .authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    protected DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);

        return provider;
    }
//
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//   UserDetails festus =  User.builder()
//                .username("festus")
//                .password(passwordEncoder.encode("password"))
//               // .roles(USER.name())
//                .authorities(USER.getGrantedAuthorities())
//                .build();
//
//     UserDetails alvin = User.builder()
//             .username("alvin")
//             .password(passwordEncoder.encode("password"))
//             //.roles(ADMIN.name())
//             .authorities(ADMIN.getGrantedAuthorities())
//             .build();
//
//        UserDetails tom = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("password"))
//               // .roles(ADMINTRAINEE.name())
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(festus, alvin, tom);
//
//
//    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/", "index", "/css/*","/js/*").permitAll()
//                .antMatchers("/product/**").hasRole(USER.name())
////                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
//                .anyRequest()
//                .authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                .permitAll()
//                .defaultSuccessUrl("/products",true)
//                .passwordParameter("password")
//                .usernameParameter("username")
//                .and()
//                .rememberMe().tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
//                .key("somethingsecured")
//                .rememberMeParameter("remember-me")
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID","remember-me")
//                .logoutSuccessUrl("/login");
//
//
//    }
}
