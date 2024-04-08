package com.example.userservice.security;

import org.springframework.security.web.authentication.AuthenticationFilter;// package com.example.userservice.security;

import com.example.userservice.service.UserService;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private final UserService userService;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final Environment env;


	// @Override
	// protected void configure(HttpSecurity http) throws Exception {
	// 	http.csrf().disable();

		// http.authorizeRequests().antMatchers("/users/**").permitAll();
		// http.authorizeRequests().antMatchers("/actuator/**").permitAll();
		// http.authorizeRequests().antMatchers("/health-check/**").permitAll();
		// http.authorizeRequests().antMatchers("/h2-console/**").permitAll();
		// http.authorizeRequests().antMatchers("/error/**").permitAll();
		// http.authorizeRequests().antMatchers("/**")
		// 	//                .hasIpAddress(env.getProperty("gateway.ip")) // <- IP 변경
		// 	//                .hasIpAddress("127.0.0.1") // <- IP 변경
		// 	.access("hasIpAddress('127.0.0.1')")
		// 	.and()
		// 	.addFilter(getAuthenticationFilter());

	// 	       http.authorizeRequests().antMatchers("/users")
	// 	               .hasIpAddress(env.getProperty("gateway.ip")) // <- IP 변경
	// 	               .and()
	// 	               .addFilter(getAuthenticationFilter());
	//
	// 	       http.authorizeRequests().anyRequest().denyAll();
	//
	// 	http.headers().frameOptions().disable();
	// }

	   // private com.example.userservice.security.AuthenticationFilter getAuthenticationFilter() throws Exception {
	   //     com.example.userservice.security.AuthenticationFilter authenticationFilter =
	   //             new com.example.userservice.security.AuthenticationFilter(authenticationManager(), userService, env);
	   //
	   //     return authenticationFilter;
	   // }

	// @Override
	// protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	// 	auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
	// }


}