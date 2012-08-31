package org.cloudfoundry.identity.web;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.saml2.core.impl.NameIDImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.client.RestOperations;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

@Controller
@Component
@SessionAttributes(value = "cookie")
public class CloudfoundryServiceProviderController {

    private final Logger log = LoggerFactory.getLogger(CloudfoundryServiceProviderController.class);
    
	private static final String CONTENT_LENGTH = "Content-Length";

	private static final String TRANSFER_ENCODING = "Transfer-Encoding";

    @Autowired
	private RestOperations authorizationTemplate = null;
	
	private String uaaHost = "http://uaa.cf102.dev.las01.vcsops.com";
	
	private static final String HOST = "Host";
	
	@RequestMapping(value = "/oauth/authorize", params = "response_type", method = RequestMethod.GET)
	public ModelAndView startAuthorization(HttpServletRequest request, @RequestParam Map<String, String> parameters,
			Map<String, Object> model, @RequestHeader HttpHeaders headers, Principal principal) {

		Authentication token = (ExpiringUsernameAuthenticationToken) principal;
		String username = ((NameIDImpl)token.getPrincipal()).getValue();
				
		MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
		map.setAll(parameters);
		if (principal != null) {
			map.set("login", "{\"username\":\"" + username + "\"}");
		}

		HttpHeaders requestHeaders = new HttpHeaders();
		try {
			requestHeaders.putAll(getRequestHeaders(headers));
		} catch (URISyntaxException e) {
			throw new InternalError("Internal Server Error");
		}
		requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		requestHeaders.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		requestHeaders.remove("Cookie");

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = authorizationTemplate.exchange(uaaHost + "/oauth/authorize", HttpMethod.POST,
				new HttpEntity<MultiValueMap<String, String>>(map, requestHeaders), Map.class);

		saveCookie(response.getHeaders(), model);

		@SuppressWarnings("unchecked")
		Map<String, Object> body = (Map<String, Object>) response.getBody();
		if (body != null) {
			// User approval is required
			log.debug("Response: " + body);
			model.putAll(body);
			return new ModelAndView("access_confirmation", model);
		}

		String location = response.getHeaders().getFirst("Location");
		if (location != null) {
			return new ModelAndView(new RedirectView(location));
		}

		throw new IllegalStateException("Neither a redirect nor a user approval");
    }

	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST, params = "user_oauth_approval")
	@ResponseBody
	public ResponseEntity<byte[]> approveOrDeny(HttpServletRequest request, HttpEntity<byte[]> entity,
			Map<String, Object> model, SessionStatus sessionStatus) throws Exception {
		sessionStatus.setComplete();
		return passthru(request, entity, model);
	}

	@RequestMapping(value = { "/login", "/login_info" }, method = RequestMethod.GET)
	public String prompts(HttpServletRequest request, @RequestHeader HttpHeaders headers, Model model,
			Principal principal) throws Exception {
		String path = extractPath(request);
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = authorizationTemplate.exchange(uaaHost + "/" + path, HttpMethod.GET,
				new HttpEntity<Void>(null, getRequestHeaders(headers)), Map.class);
		@SuppressWarnings("unchecked")
		Map<String, Object> body = (Map<String, Object>) response.getBody();
		model.addAllAttributes(body);
		if (principal == null) {
			return "login";
		}
		return "home";
	}
	
	@RequestMapping(value = { "/" }, method = RequestMethod.GET)
	public String home(HttpServletRequest request, @RequestHeader HttpHeaders headers, Model model,
			Principal principal) throws Exception {
		if (principal == null) {
			return "login";
		}
		return "home";
	}
	
//	@RequestMapping(value = { "/error" }, method = RequestMethod.GET)
//	public String error(HttpServletRequest request, @RequestHeader HttpHeaders headers, Model model,
//			Principal principal) throws Exception {
//		return "error";
//	}
	
	private void saveCookie(HttpHeaders headers, Map<String, Object> model) {
		// Save back end cookie for later
		String cookie = headers.getFirst("Set-Cookie");
		if (cookie != null) {
			log.debug("Saved back end cookie: " + cookie);
			model.put("cookie", cookie);
		}
	}

	private HttpHeaders getRequestHeaders(HttpHeaders headers) throws URISyntaxException {
		HttpHeaders outgoingHeaders = new HttpHeaders();
		outgoingHeaders.putAll(headers);
		outgoingHeaders.remove(HOST);
		outgoingHeaders.set(HOST, (new URI(uaaHost).getHost()));
		log.debug("Outgoing headers: " + outgoingHeaders);
		return outgoingHeaders;
	}
	
	@ExceptionHandler(OAuth2Exception.class)
	public ModelAndView handleOAuth2Exception(OAuth2Exception e, ServletWebRequest webRequest) throws Exception {
		log.info("OAuth2 error" + e.getSummary());
		webRequest.getResponse().setStatus(e.getHttpErrorCode());
		return new ModelAndView("forward:/", Collections.singletonMap("error", e));
	}
	
	private ResponseEntity<byte[]> passthru(HttpServletRequest request, HttpEntity<byte[]> entity,
			Map<String, Object> model) throws Exception {

		String path = extractPath(request);

		HttpHeaders requestHeaders = new HttpHeaders();
		requestHeaders.putAll(getRequestHeaders(entity.getHeaders()));
		// Get back end cookie if saved in session
		String cookie = (String) model.get("cookie");
		if (cookie != null) {
			log.debug("Found back end cookie: " + cookie);
			requestHeaders.set("Cookie", cookie);
		}

		ResponseEntity<byte[]> response = authorizationTemplate.exchange(uaaHost + "/" + path, HttpMethod.POST,
				new HttpEntity<byte[]>(entity.getBody(), requestHeaders), byte[].class);
		HttpHeaders outgoingHeaders = getResponseHeaders(response.getHeaders());
		return new ResponseEntity<byte[]>(response.getBody(), outgoingHeaders, response.getStatusCode());

	}
	
	private HttpHeaders getResponseHeaders(HttpHeaders headers) {
		// Some of the headers coming back are poisonous apparently (content-length?)...
		HttpHeaders outgoingHeaders = new HttpHeaders();
		outgoingHeaders.putAll(headers);
		if (headers.getContentLength() >= 0) {
			outgoingHeaders.remove(CONTENT_LENGTH);
		}
		if (headers.containsKey(TRANSFER_ENCODING)) {
			outgoingHeaders.remove(TRANSFER_ENCODING);
		}
		return outgoingHeaders;
	}
	
	private String extractPath(HttpServletRequest request) {
		String query = request.getQueryString();
		try {
			query = query == null ? "" : "?" + URLDecoder.decode(query, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Cannot decode query string: " + query);
		}
		String path = request.getRequestURI() + query;
		String context = request.getContextPath();
		path = path.substring(context.length());
		if (path.startsWith("/")) {
			// In the root context we have to remove this as well
			path = path.substring(1);
		}
		log.debug("Path: " + path);
		return path;
	}


	public RestOperations getAuthorizationTemplate() {
		return authorizationTemplate;
	}

	public void setAuthorizationTemplate(RestOperations authorizationTemplate) {
		this.authorizationTemplate = authorizationTemplate;
	}
}
