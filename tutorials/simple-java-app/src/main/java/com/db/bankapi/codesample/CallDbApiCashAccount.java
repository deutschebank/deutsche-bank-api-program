/*******************************************************************************
 *  Copyright 2020 Deutsche Bank AG
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

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * To run this application you have to change 4 parameters to run this application:
 * The variables fkn and pin from one of your test user accounts as well as the value of the query
 * parameter "client_id" in Step1 with the clientId from one of your simulation apps which uses the implicit
 * OAuth2 grant type and the query parameter "redirect_uri" with one corresponding redirectUri of your chosen app.
 *
 */
public class CallDbApiCashAccount {

	private final String SESSION_ID = "JSESSIONID";

	//The current session is stored in a cookie.
	private NewCookie sessionId;

	public static void main(String[] args) {

		CallDbApiCashAccount callDbApiCashAccount = new CallDbApiCashAccount();

		//Please login to activate your test user to get your fkn and pin
		String fkn = "Your fkn from your generated test user account";
		String pin = "Your pin from your generated test user account";

		//Step 1
		Response response = callDbApiCashAccount.authorizationRequest();

		//Step 2
		Object [] responseAndRedirectUri = callDbApiCashAccount.redirectToLoginPage(response);

		//Step 3.1
		response = callDbApiCashAccount.loginAndAuthorize(responseAndRedirectUri, fkn, pin);

		//Step 3.2
		response = callDbApiCashAccount.grantAccess(response);

		//Step 4
		String accessToken = callDbApiCashAccount.returnToRedirectAndGetAccessToken(response);

		//Step 5
		callDbApiCashAccount.callCashAccountsEndpoint(accessToken);
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
				.connectTimeout(10, TimeUnit.SECONDS)
				.readTimeout(10, TimeUnit.SECONDS)
				.build()
				.target("https://simulator-api.db.com/gw/oidc/authorize");

		//Please login to activate your client. The client_id and redirect_uri will be replaced with your activated client.
		Response response = wt.property("jersey.config.client.followRedirects", false)
				.queryParam("response_type", "token")
				.queryParam("client_id", "Your clientId from your generated client")
				.queryParam("redirect_uri", "Your redirect from your generated client")
				.queryParam("scope", "read_accounts")
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
		response =  ClientBuilder.newClient().target(uri)
				.property("jersey.config.client.followRedirects", false)
				.request()
				.cookie(sessionId).get();

		updateSessionId(response);

		System.out.println("Step 2 executed redirected to login page.");
		return new Object[] {response, uri};
	}

	/**
	 *  Step 3.1
	 *  Executes the login with your default test users' fkn and pin and updates the session.
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
				.property("jersey.config.client.followRedirects", false)
				.request()
				.cookie(sessionId)
				.post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

		updateSessionId(response);

		if(response.getLocation().toString().contains("noaccess")
				|| response.getLocation().toString().contains("commonerror")
				|| response.getLocation().toString().contains("failure")) {
			String message = response.readEntity(String.class);
			System.out.println("Failed to login as expected " + username + " loc = " + response.getLocation() + " msg = " + message);
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
		response = ClientBuilder.newClient().target(uri)
				.property("jersey.config.client.followRedirects", false)
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

			response = ClientBuilder.newClient().target(postUrl).property("jersey.config.client.followRedirects", false)
					.request().cookie(sessionId).post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

			System.out.println("Step 3.2 authorize access with requested scope read_accounts on consent screen.");
			return response;

		}
		return null;
	}

	/**
	 * Step 4
	 * After successful authorization in Step 3 get the access token from the HTTP Location attribute
	 * of the {@link Response}.
	 *
	 * @return The access token or null.
	 */
	public String returnToRedirectAndGetAccessToken(Response response) {
		URI loc = response.getLocation();
		String accessToken = null;
		if(loc != null) {
			accessToken = getAccessToken(loc.toString());
		}
		System.out.println("Successfully get an access token.");
		return accessToken;
	}

	/**
	 * Step 5
	 * Call the cash accounts endpoint of the dbAPI to get the available cash accounts
	 * from your default test users' account.
	 * You should get 2 accounts from your default test users' account.
	 *
	 * The Correlation-Id in the header is optional. It's a free form key controlled by the caller e.g. UUID.
	 * It makes it easy to track an individual request across your and our system components, or to track multiple
	 * requests belonging to one business process.
	 *
	 * @param accessToken The bearer token from Step 4.
	 */
	private void callCashAccountsEndpoint(String accessToken) {

		WebTarget wt = ClientBuilder.newBuilder()
				.connectTimeout(10, TimeUnit.SECONDS)
				.readTimeout(10, TimeUnit.SECONDS)
				.build()
				.target("https://simulator-api.db.com/gw/dbapi/banking/cashAccounts/v2");

		String correlationId = UUID.randomUUID().toString();

		Response response = wt.request()
				.header("Authorization", "Bearer " + accessToken)
				.header("Correlation-Id", correlationId)
				.accept(MediaType.APPLICATION_JSON)
				.get();

		System.out.println("Calling dbAPI cashAccounts endpoint done. The JSON response is:");
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
	static String getCsrf(String webPage) {
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
	protected URI getFormPostUrl(URI target, String webPage) {
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
	 * Helper method to extract the access token from the given string.
	 *
	 * @param uri The URI which contains the access token.
	 * @return The access token if available.
	 */
	protected String getAccessToken(String uri) {
		String accessToken = getTokenFromString(uri, "access_token=([\\d\\w\\.-]+)&");
		System.out.println("access_token = " + accessToken);
		return accessToken;
	}

	/**
	 * Helper method. Get first match from given String.
	 *
	 * @param uri The string which have to be analyzed.
	 * @param pattern The Regex-Pattern for searching.
	 * @return Get the first match of the given String or null.
	 */
	protected String getTokenFromString(String uri, String pattern) {
		Pattern tokenPattern = Pattern.compile(pattern);
		Matcher tokenMatcher = tokenPattern.matcher(uri);
		if (tokenMatcher.find()) {
			return tokenMatcher.group(1);
		}
		return null;
	}

}