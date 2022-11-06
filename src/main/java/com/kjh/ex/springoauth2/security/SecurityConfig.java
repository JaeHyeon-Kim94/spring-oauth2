package com.kjh.ex.springoauth2.security;

import com.kjh.ex.springoauth2.service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import static com.kjh.ex.springoauth2.security.SocialType.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/"
                        , "/css/**"
                        , "*/images/**"
                        , "/js/**"
                        , "/h2-console/**"
                        , "/favicon.ico/**").permitAll()
                .antMatchers("/google").hasAuthority(GOOGLE.getRoleType())
                .antMatchers("/naver").hasAuthority(NAVER.getRoleType())
                .antMatchers("/kakao").hasAuthority(KAKAO.getRoleType())
                .anyRequest().authenticated()
                .and()
                    .oauth2Login()
                    .userInfoEndpoint().userService(new CustomOAuth2UserService())
                .and()
                    .defaultSuccessUrl("/loginSuccess")
                    .failureUrl("/loginFailure")
                .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));

        return http.build();
    }

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository(
//
//    ){
//
//    }
}
