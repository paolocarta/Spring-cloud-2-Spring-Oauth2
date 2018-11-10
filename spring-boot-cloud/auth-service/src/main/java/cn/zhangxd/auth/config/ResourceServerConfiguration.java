package cn.zhangxd.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

	private static final String RESOURCE_ID = "*";

	@Autowired
	private ResourceServerTokenServices tokenServices;

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {

		resources.resourceId(RESOURCE_ID)
				.stateless(true)
				.tokenServices(tokenServices);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
				.antMatcher("/auth")
				.authorizeRequests()
				.anyRequest()
				.authenticated();
	}

	 @Bean
	 public LogoutSuccessHandler customLogoutSuccessHandler() {
	 return new CustomLogoutSuccessHandler();
	 }
	
	 @Bean
	 public AuthenticationEntryPoint customAuthenticationEntryPoint() {
	 return new CustomAuthenticationEntryPoint();
	 }

}
