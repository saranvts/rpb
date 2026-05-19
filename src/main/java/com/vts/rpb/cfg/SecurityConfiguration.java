package com.vts.rpb.cfg;

import com.vts.rpb.authenticate.LoginSuccessHandler;
import com.vts.rpb.authenticate.UserLogoutHandler;
import com.vts.rpb.authenticate.UserLogoutSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration
{
	@Value("${LabCode}")
	private String labCode;

	@Autowired
	private LoginSuccessHandler loginSuccessHandler;

	@Autowired
	private UserLogoutSuccessHandler userLogoutSuccessHandler;

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception
	{
		http.authorizeHttpRequests(auth -> auth
						.requestMatchers("/", "/login", "/RPB", "HeaderHelpAction.htm", "/webjars/**", "/resources/**", "/view/**", "/sessionExpired").permitAll()
						.anyRequest().authenticated()
				)
				.logout(logout -> logout
						.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
						.addLogoutHandler(userLogoutHandler())
						.logoutSuccessHandler(userLogoutSuccessHandler)
				)
				.oauth2Login(oauth -> oauth
						.loginPage("/login")
						.successHandler(loginSuccessHandler)
				)
				
				.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
				
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
						.invalidSessionUrl("/sessionExpired")
						.sessionConcurrency(concurrency -> concurrency
								.maximumSessions(5)
								.maxSessionsPreventsLogin(false)
						));

		return http.build();
	}

	@Bean
	public AuthenticationProvider authenticationProvider()
	{
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService());
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		return daoAuthenticationProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationProvider authenticationProvider)
	{
		return new ProviderManager(Collections.singletonList(authenticationProvider));
	}

	@Bean
	@Primary
	UserDetailsService userDetailsService()
	{
		return new UserDetailsService() {
			@Override
			public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				return null;
			}
		};
	}

	@Bean
	@Primary
	PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}

	@Bean
	LogoutHandler userLogoutHandler()
	{
		return new UserLogoutHandler();
	}
}