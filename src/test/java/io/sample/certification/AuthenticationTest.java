package io.sample.certification;

import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class AuthenticationTest {

	@BeforeClass
	public static void beforeClass() {
		System.out.println("This is the first excuted");
	}

	@Before
	public void before() {
		System.out.println("Before");
	}

	@Test
	public void testSslSocketAsX509() {

		String storeFile = "/usr/local/temp/test.crt";
		String targetUrl = "https://localhost/test";
		Map<String, String> map = null;
		InputStreamReader streamReader = null;
		try {

			map = new HashMap<String, String>();
			map.put("key", "value");

			streamReader = Authentication.sslSocketAsX509(storeFile, targetUrl, map);

			JSONParser parser = new JSONParser();
			JSONObject spUserAttributes = (JSONObject)parser.parse(streamReader);
			String resutl = (String) spUserAttributes.get("test");

			Assert.assertNull(resutl);

		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("This is the test");
	}

	@Test
	public void testSslSocketAsSunX509() {

		String storeFile = "/usr/local/temp/test.crt";
		String storePass = ""; // or test
		String targetUrl = "https://localhost/test";
		Map<String, String> map = null;
		InputStreamReader streamReader = null;
		try {

			map = new HashMap<String, String>();
			map.put("key", "value");

			streamReader = Authentication.sslSocketAsSunX509(storeFile, storePass, targetUrl, map);

			JSONParser parser = new JSONParser();
			JSONObject spUserAttributes = (JSONObject)parser.parse(streamReader);
			String resutl = (String) spUserAttributes.get("test");
			
			Assert.assertNull(resutl);

		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("This is the test");
	}

	@After
	public void after() {
		System.out.println("Before");
	}

	@AfterClass
	public static void afterClass() {
		System.out.println("This is the end excuted");
	}

}