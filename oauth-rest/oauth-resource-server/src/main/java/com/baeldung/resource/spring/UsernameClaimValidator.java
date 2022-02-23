package com.baeldung.resource.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

class UsernameClaimValidator implements OAuth2TokenValidator<Jwt> {
	OAuth2Error error = new OAuth2Error("InValidAccess", "User donot have access.", null);

	private String USER_CLAIM_KEY = "preferred_username";
	private String claimValidationRule = "@baeldung.com";

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {

		if (jwt.hasClaim(USER_CLAIM_KEY) && jwt.getClaim(USER_CLAIM_KEY).toString().endsWith(claimValidationRule)) {
			return OAuth2TokenValidatorResult.success();
		} else {
			return OAuth2TokenValidatorResult.failure(error);
		}
	}
}