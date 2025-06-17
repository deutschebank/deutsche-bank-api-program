/*******************************************************************************
 *  Copyright 2025 Deutsche Bank AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.db.bankapi.codesample;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.glassfish.jersey.client.ClientProperties;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * If you set up this application in your local environment/IDE, we recommend maven as build tool with the following
 * dependency configurations:
 * <pre>
 *  <dependencies>
 * 		<dependency>
 * 			<groupId>org.glassfish.jersey.core</groupId>
 * 			<artifactId>jersey-client</artifactId>
 * 			<version>3.1.10</version>
 * 		</dependency>
 * 		<dependency>
 * 			<groupId>org.glassfish.jersey.inject</groupId>
 * 			<artifactId>jersey-hk2</artifactId>
 * 			<version>3.1.10<</version>
 * 		</dependency>
 * 		<dependency>
 * 			<groupId>org.glassfish.jersey.media</groupId>
 * 			<artifactId>jersey-media-json-jackson</artifactId>
 * 			<version>3.1.10<</version>
 * 		</dependency>
 * 		<dependency>
 * 			<groupId>jakarta.activation</groupId>
 * 			<artifactId>jakarta.activation-api</artifactId>
 * 			<version>2.1.3</version>
 * 		</dependency>
 * 		<dependency>
 * 			<groupId>commons-codec</groupId>
 * 			<artifactId>commons-codec</artifactId>
 * 			<version>1.18.0</version>
 * 		</dependency>
 * 	</dependencies>
 * </pre>
 * To run this sample application you have to adapt 4 parameters:
 *
 * First, the variables fkn and pin from one of your Deutsche Bank test user accounts which you created
 * on https://developer.db.com/dashboard/testusers
 *
 * Then replace the query parameter "client_id" in Step 1 as well as in Step 5 with the clientId from one of your simulation apps which uses
 * the Authorization Code Flow with Proof Key for Code Exchange (PKCE) grant type. The last parameter which has to be adapted is the query parameter "redirect_uri"
 * with one corresponding redirect URIs of your chosen app. This parameter is also used in Step 1 and Step 5 of this sample application.
 *
 * Using the Authorization Code Flow with PKCE, prevents CSRF and authorization code injection attacks!
 * In this example a client secret is not used. We presuppose that this application is a public client instead of a confidential client.
 * If you develop a confidential client, you can use a client secret. Public clients are not allowed to use a client secret because they can't keep the client secret safely.
 * For more information read our differences between a public and confidential client in our FAQ on https://developer.db.com/faq.
 * The PKCE extension requires an extra step at the beginning and an extra verification at the end:
 *
 * First create a high-entropy cryptographic random string between 43 and 128 characters long using
 * the unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~". This is your code verifier.
 *
 * From your code verifier you've to create a code challenge which has to be hashed with SHA-256 and then sent as Base64 url encoded string.
 * Both are sent to the authorisation server within different steps of the OAuth 2.0 flow to allow the authorisation
 * server to verify that it's communicating with your app only.
 *
 * Attention!! Use https://simulator-api.db.com/gw/oidc/managegrants/ to remove the consent from
 * your client id (app) you use in this example if it's given before. Otherwise, you will get a NullPointerException after granting
 * access to the scopes because you already granted the scope read_accounts before!
 *
 * If you're behind a proxy, you have to configure a proxy for each HTTP connection below. A proxy can be configured like this:
 *
 * <pre>
 * Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("YOUR_PROXY_HOST", YOUR_PROXY_PORT));
 * Client client = ClientBuilder.newClient(new ClientConfig()
 *                  .connectorProvider(new HttpUrlConnectorProvider()
 *                  .connectionFactory(url -> (HttpURLConnection) url.openConnection(proxy))));
 * </pre>
 */
public class CallDbApiCashAccount {

	private static final String SESSION_ID = "JSESSIONID";
	private static final String BASE_URL = "https://simulator-api.db.com";

	private String codeVerifier;
	private String codeChallenge;

	//The current session is stored in a cookie.
	private NewCookie sessionId;

	public static void main(String[] args) {

		CallDbApiCashAccount callDbApiCashAccount = new CallDbApiCashAccount();

		//Login on https://developer.db.com/dashboard/testusers to get the credentials
		//of one of your Deutsche Bank test user(s)
		String fkn = "Your fkn from your generated Deutsche Bank test user account";
		String pin = "Your pin from your generated Deutsche Bank test user account";

		//Pre required step 0.1 create code verifier
		callDbApiCashAccount.generateRandomCodeVerifier();

		//Pre required step 0.2 create a code challenge from your code verifier
		callDbApiCashAccount.createCodeChallenge();

		//Step 1
		Response response = callDbApiCashAccount.authorizationRequest();

		//Step 2
		Object [] responseAndRedirectUri = callDbApiCashAccount.redirectToLoginPage(response);

		//Step 3.1
		response = callDbApiCashAccount.loginAndAuthorize(responseAndRedirectUri, fkn, pin);

		//Step 3.2
		response = callDbApiCashAccount.grantAccess(response);

		//Step 4
		//Get Code
		String code = callDbApiCashAccount.getCode(response);

		//Step 5
		//Get Access Token
		response = callDbApiCashAccount.requestAccessTokensFromCode(code);

		//Step 6
		//Get access token from JSON result of Deutsche Bank authorisation service
		String accessToken = callDbApiCashAccount.getAccessTokenFromJson(response);

		//Step 7
		callDbApiCashAccount.callCashAccountsEndpoint(accessToken);
	}

	/**
	 * Generates a random Base64 encoded code verifier which has to be used in Step 5 as a request parameter.
	 */
	private void generateRandomCodeVerifier() {
		SecureRandom sr = new SecureRandom();
		byte[] code = new byte[32];
		sr.nextBytes(code);
		this.codeVerifier = java.util.Base64.getEncoder().encodeToString(code);
		System.out.println("Pre required Step 0.1 generated a random code verifier with value: " + this.codeVerifier);
	}

	/**
	 * Produces a code challenge from a code verifier, to be hashed with SHA-256 and encode it with Base64 to be URL safe.
	 * This code challenge has to be used in Step 1 as request parameter.
	 */
	private void createCodeChallenge() {
		try {
			byte[] bytes = codeVerifier.getBytes(StandardCharsets.UTF_8);
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(bytes, 0, bytes.length);
			byte[] digest = md.digest();
			this.codeChallenge = Base64.encodeBase64URLSafeString(digest);
			System.out.println("Pre required Step 0.2 generated code challenge with the following value from the provided code verifier: " + this.codeChallenge);
		} catch (NoSuchAlgorithmException e2) {
			System.out.println("Wrong algorithm to encode: " + e2);
		}
	}

	/**
	 * Step 1
	 * Executes the OAuth2.0 initial authorization request.
	 * Saves the session in a Cookie. Saving the session is optional and not part of
	 * the OAuth2.0 specification!
	 *
	 * The scope request parameter is optional. The state request parameter is
	 * optional too but recommended to e.g., increase the application's resilience
	 * against CSRF attacks. All other request parameter are required!
	 *
	 * @return The {@link Response} from the OAuth2.0 initial authorization request.
	 */
	private Response authorizationRequest() {
		WebTarget wt = ClientBuilder.newBuilder()
				.build()
				.target(BASE_URL + "/gw/oidc/authorize");

				//Please login to activate your client. The client_id and redirect_uri will be replaced with your activated client.
				Response response = wt.property(ClientProperties.FOLLOW_REDIRECTS, false)
						.queryParam("response_type", "code")
						.queryParam("client_id", "Your clientId from your generated client")
						.queryParam("redirect_uri", "One of your redirect URI(s) from your generated client")
						.queryParam("scope", "read_accounts")
						.queryParam("code_challenge_method", "S256")
						.queryParam("code_challenge", codeChallenge)
						.queryParam("state", "0.21581183640296075")
						.request()
						.get();

		updateSessionId(response);
		System.out.println("Step 1 executed authorizeRequest.");
		return response;
	}

	/**
	 * Step 2
	 * Redirect to the login page and updating the session in the Cookie.
	 *
	 * @param response The {@link Response} from the initial OAuth2.0 authorization request.
	 * @return An array which contains the {@link URI} and the {@link Response} from
	 * the redirection.
	 */
	private Object[] redirectToLoginPage(Response response) {
		/*
		 * We have to follow the redirect manually here because the automatic
		 * redirect in the HttpUrlConnection doesn't forward the cookie, i.e.
		 */
		URI uri = response.getLocation();
		if(!uri.isAbsolute()) {
			uri = URI.create(BASE_URL).resolve(uri);
		}

		response =  ClientBuilder.newClient().target(uri)
				.property(ClientProperties.FOLLOW_REDIRECTS, false)
				.request()
				.cookie(sessionId).get();

		updateSessionId(response);

		System.out.println("Step 2 executed redirected to login page.");
		return new Object[] {response, uri};
	}

	/**
	 * Step 3.1
	 * Executes the login with your default test users' fkn and pin and updates the session.
	 *
	 * @param responseAndRedirectUri contains the {@link Response} and {@link URI} from step 2.
	 * @param username the fkn of your default test user.
	 * @param password the pin of your default test user.
	 * @return the {@link Response} after the login.
	 */
	private Response loginAndAuthorize(Object [] responseAndRedirectUri, String username, String password) {
		Response response = (Response) responseAndRedirectUri[0];
		URI uri = (URI) responseAndRedirectUri[1];

		// extract CSRF token for this session
		String webPage = response.readEntity(String.class);
		String csrf = getCsrf(webPage);

		//get the action from the login page
		URI postUrl = getFormPostUrl(uri, webPage);
		// post login
		Form form = new Form();
		form.param("username", username);
		form.param("password", password);
		form.param("_csrf", csrf);
		form.param("submit", "Login");

		response = ClientBuilder.newClient().target(postUrl)
				.property(ClientProperties.FOLLOW_REDIRECTS, false)
				.request()
				.cookie(sessionId)
				.post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

		updateSessionId(response);

		if(response.getLocation().toString().contains("noaccess")
				|| response.getLocation().toString().contains("commonerror")
				|| response.getLocation().toString().contains("failure")) {
			System.out.println("Failed to login with username: \"" + username + "\"");
		}

		System.out.println("Step 3.1 login with fkn and pin and authorization done.");
		return  response;
	}

	/**
	 * Step 3.2
	 * Updates the session.
	 * Authorize access with the requested scope(s) in a dbAPI-prompted screen (consent screen).
	 * The scope (read_accounts) was requested in Step 1.
	 *
	 * @param response The {@link Response} after the login from step 3.1.
	 * @return The {@link Response} after authorize and give access for the (allowed) scope(s).
	 */
	private Response grantAccess(Response response) {
		URI uri = response.getLocation();
		if(!uri.isAbsolute()) {
			uri = URI.create(BASE_URL).resolve(uri);
		}

		response = ClientBuilder.newClient().target(uri)
				.property(ClientProperties.FOLLOW_REDIRECTS, false)
				.request().cookie(sessionId).get();
		updateSessionId(response);

		// grant access
		if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {

			String webPage = response.readEntity(String.class);
			String csrf = getCsrf(webPage);
			//get the action from the consent page
			URI postUrl = getFormPostUrl(uri, webPage);
			updateSessionId(response);

			// post consent
			Form form = new Form();
			form.param("user_oauth_approval", "true");
			form.param("_csrf", csrf);
			// give the consent once
			form.param("remember", "none");
			form.param("scope_read_accounts" , "read_accounts");

			response = ClientBuilder.newClient().target(postUrl).property(ClientProperties.FOLLOW_REDIRECTS, false)
					.request().cookie(sessionId).post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

			System.out.println("Step 3.2 authorize access with requested scope read_accounts on consent screen.");
			return response;

		}
		return null;
	}

	/**
	 * Step 4
	 * After granting access, the Deutsche Bank API Program authorisation service redirects the user to
	 * the redirect_uri to receive the code.
	 *
	 * @param response
	 * @return
	 */
	private String getCode(Response response) {
		String responseLocationAfterGrantingAccess = response.getLocation().toString();
		String code = getCodeFromRedirect(responseLocationAfterGrantingAccess);
		System.out.println("Step 4 get the code after authorization and redirect: " + code);
		return code;
	}

	/**
	 * Step 5
	 * Request access token with given code using the provided code verifier.
	 *
	 * @param code
	 * @return
	 * @throws IOException
	 */
	private Response requestAccessTokensFromCode(String code) {
		Form form = new Form();
		form.param("grant_type", "authorization_code");
		form.param("code", code);
		form.param("code_verifier", codeVerifier);
		form.param("client_id", "Your clientId from your generated client");
		form.param("redirect_uri", "One of your redirect URI(s) from your generated client");

		// 4.1.3. Access Token Request
		Response response = ClientBuilder.newClient()
				.target(BASE_URL + "/gw/oidc/token")
				.property(ClientProperties.FOLLOW_REDIRECTS, false)
				.request()
				.post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

		updateSessionId(response);
		System.out.println("Step 5 request access token with given code: " + code + " and code verifier: " + codeVerifier);
		return response;
	}

	/**
	 * Step 6
	 * Extract the access token from the JSON response of the Deutsche Bank authorisation service.
	 *
	 * @param response
	 * @return the bearer access token
	 */
	private String getAccessTokenFromJson(Response response) {
		String responseWithAccessToken  = response.readEntity(String.class);
		ObjectMapper mapper = new ObjectMapper();
		JsonNode jsonNode = null;
		try {
			jsonNode = mapper.readTree(responseWithAccessToken);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		String accessToken = jsonNode.get("access_token").textValue();
		System.out.println("Step 6 extracted Bearer access token with value: " + accessToken);
		return accessToken;
	}

	/**
	 * Step 7
	 * Call the cash accounts endpoint of the dbAPI to get the available cash accounts from your chosen Deutsche Bank
	 * test users' account.
	 *
	 * @param accessToken The Bearer access token from Step 6.
	 */
	private void callCashAccountsEndpoint(String accessToken) {
		WebTarget wt = ClientBuilder.newBuilder()
				.build()
				.target(BASE_URL + "/gw/dbapi/banking/cashAccounts/v2");

		Response response = wt.request()
				.header("Authorization", "Bearer " + accessToken)
				.accept(MediaType.APPLICATION_JSON)
				.get();

		System.out.println("Step 7 calling dbAPI cashAccounts endpoint done. The JSON response is:");
		String jsonResponse = response.readEntity(String.class);
		System.out.println(jsonResponse);
	}

	/**
	 * Get sessionId from cookie from response and set local sessionId.
	 *
	 * @param response The current {@link Response}.
	 */
	private void updateSessionId(Response response) {
		NewCookie cookie = response.getCookies().get(SESSION_ID);
		if(cookie != null) {
			sessionId = cookie;
		}
	}

	/**
	 * Just for internal use to avoid potential CSRF attacks .
	 * You can read the RFC against CSRF attacks here: https://tools.ietf.org/html/rfc6749.
	 *
	 * @param webPage The login or consent screen.
	 * @return The CSRF code if found, null else.
	 */
	private String getCsrf(String webPage) {
		Pattern p = Pattern.compile(" name=\"_csrf\" value=\"(.*?)\"");
		Matcher m = p.matcher(webPage);
		if ( m.find() ) {
			return m.group(1);
		}
		return null;
	}

	/**
	 * Helper method. Get URI that is called from action in given HTML page.
	 *
	 * @param target  The target {@link URI}.
	 * @param webPage The login or consent screen.
	 * @return
	 */
	private URI getFormPostUrl(URI target, String webPage) {
		Pattern pattern = Pattern.compile("action=\"(.+?)\"");
		Matcher matcher = pattern.matcher(webPage);
		if ( matcher.find() ) {
			String uf = matcher.group(1);
			URI uri = URI.create(uf);
			if(!uri.isAbsolute()) {
				URI targetUri = target.resolve(uri);
				return targetUri;
			}
			return uri;
		}
		return null;
	}

	/**
	 * Helper method. Extracts code from given string
	 *
	 * @param uri
	 * @return
	 */
	private String getCodeFromRedirect(String uri) {
		return getTokenFromString(uri, "code=([\\d\\w\\.-]+)&");
	}

	/**
	 * Helper method. Get first match from given String.
	 *
	 * @param uri The string which have to be analyzed.
	 * @param pattern The Regex-Pattern for searching.
	 * @return Get the first match of the given String or null.
	 */
	private String getTokenFromString(String uri, String pattern) {
		Pattern tokenPattern = Pattern.compile(pattern);
		Matcher tokenMatcher = tokenPattern.matcher(uri);
		if (tokenMatcher.find()) {
			return tokenMatcher.group(1);
		}
		return null;
	}

}
