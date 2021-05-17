package com.learningspringsecurity.demospringsecurity.security;

import com.learningspringsecurity.demospringsecurity.auth.ApplicationUserService;
import com.learningspringsecurity.demospringsecurity.jwt.JwtConfig;
import com.learningspringsecurity.demospringsecurity.jwt.JwtTokenVerifier;
import com.learningspringsecurity.demospringsecurity.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
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

import static com.learningspringsecurity.demospringsecurity.security.ApplicationUserRole.STUDENT;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {



    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;


    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }





    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http

                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated();




                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                //.and()

                /*
                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                */

                 /*
                .and()
                //.httpBasic();

                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses",true)
                .and()
                .rememberMe().tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                .key("somthingverysecured")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    //.logoutRequestMatcher(new AntPathRequestMatcher("logout","GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID","remember-me")
                    .logoutSuccessUrl("/login"); //defaults to 2 weeks; */
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;





   }
}
