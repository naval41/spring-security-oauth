package com.baeldung.resource.spring;

import java.util.Collections;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;

public class AuthorityClaimAdapter implements Converter<Map<String, Object>, Map<String, Object>> {

	private final MappedJwtClaimSetConverter delegate = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
	private String claimValidationRule = "@baeldung.com";
	
	public Map<String, Object> convert(Map<String, Object> claims) {
		
		Map<String, Object> convertedClaims = this.delegate.convert(claims);
	
		if(convertedClaims.containsKey("preferred_username") && 
				convertedClaims.get("preferred_username").toString().endsWith(claimValidationRule)) {
			convertedClaims.put("scope", convertedClaims.get("scope")+" super");   // updating claim if username ends with @baeldung.com
		}
		return convertedClaims;
	}
}