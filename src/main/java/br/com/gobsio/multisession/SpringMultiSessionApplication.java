package br.com.gobsio.multisession;

import org.apache.tomcat.util.http.LegacyCookieProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
// import org.springframework.session.web.http.CookieSerializer;
// import org.springframework.session.web.http.DefaultCookieSerializer;

@SpringBootApplication
public class SpringMultiSessionApplication {

	@Bean
	public WebServerFactoryCustomizer<TomcatServletWebServerFactory> webServerFactoryCustomizer() {
		return new WebServerFactoryCustomizer<TomcatServletWebServerFactory>() {
			@Override
			public void customize(TomcatServletWebServerFactory factory) {
				TomcatServletWebServerFactory tomcat = (TomcatServletWebServerFactory) factory;
				tomcat.addContextCustomizers(context -> context.setCookieProcessor(new LegacyCookieProcessor()));
			}
		};
	}

	// @Bean
	// public CookieSerializer cookieSerializer() {
	// 	DefaultCookieSerializer serializer = new DefaultCookieSerializer();
	// 	serializer.setCookieName("SESSION");
	// 	serializer.setCookiePath("/");
	// 	serializer.setDomainNamePattern("^.+?\\.(\\w+\\.[a-z]+)$");
	// 	return serializer;
	// }

	public static void main(String[] args) {
		SpringApplication.run(SpringMultiSessionApplication.class, args);
	}

}
