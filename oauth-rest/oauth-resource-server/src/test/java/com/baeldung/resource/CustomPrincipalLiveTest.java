package com.baeldung.resource;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import io.restassured.RestAssured;
import io.restassured.response.Response;

public class CustomPrincipalLiveTest {
	
	private final static String AUTH_SERVER = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect";
	private final static String RESOURCE_SERVER = "http://localhost:8081/resource-server";
	private final static String CLIENT_ID = "newClient";
	private final static String CLIENT_SECRET = "newClientSecret";
	private final static String VALID_ACCESS_USERNAME = "valid@baeldung.com";   //new user created from Keycloak dashboard.
	private final static String VALID_ACCESS_PASSWORD = "valid";
	private final static String INVALID_ACCESS_USERNAME = "john@test.com";
	private final static String INVALID_ACCESS_PASSWORD = "123";

	@Test
	public void givenValidAccessUser_whenHavingValidPrivileged_thenOkToAccessApprovedEndPoints() {
		final String accessToken = obtainAccessToken(CLIENT_ID, VALID_ACCESS_USERNAME, VALID_ACCESS_PASSWORD);

		final Response fooResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken)
				.get(RESOURCE_SERVER + "/api/foos/1");
		assertEquals(200, fooResponse.getStatusCode());
	}
	
	@Test
	public void givenInValidAccessUser_whenHavingInValidUserName_thenDenyAccessOnAnyOfResource() {
		final String accessToken = obtainAccessToken(CLIENT_ID, INVALID_ACCESS_USERNAME, INVALID_ACCESS_PASSWORD);

		final Response fooResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken)
				.get(RESOURCE_SERVER + "/api/foos/1");
		assertEquals(403, fooResponse.getStatusCode());
	}

	private String obtainAccessToken(String clientId, String username, String password) {
		final Map<String, String> params = new HashMap<String, String>();
		params.put("grant_type", "password");
		params.put("client_id", clientId);
		params.put("username", username);
		params.put("password", password);
		params.put("scope", "read write");
		final Response response = RestAssured.given().auth().preemptive().basic(clientId, CLIENT_SECRET).and()
				.with().params(params).when().post(AUTH_SERVER + "/token");
		return response.jsonPath().getString("access_token");
	}
}
