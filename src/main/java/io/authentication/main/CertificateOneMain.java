package io.authentication.main;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class CertificateOneMain {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {

		final String storeFile = "/usr/local/temp/test.crt";
		final String storePass = "";

		KeyStore ks = KeyStore.getInstance("JKS");
		File file = new File(storeFile);
		FileInputStream fiStream = new FileInputStream(file);
		InputStream stream = new BufferedInputStream(fiStream);
		ks.load(stream, storePass.toCharArray());

		// KeyManagerFactory.getDefaultAlgorithm() = SunX509
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);

		// Create an SSLContext that uses our TrustManager
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(null, tmf.getTrustManagers(), null);

		SSLSocketFactory socketFactory = sslContext.getSocketFactory();

		URL pickUrl = new URL("https://test.ttta.tta.ya/ameblo");
		URLConnection urlConn = pickUrl.openConnection();
		HttpsURLConnection httpsURLConn = (HttpsURLConnection)urlConn;
		// True to verify certificate 
		final HostnameVerifier hv=new HostnameVerifier() {
			@Override
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};

		httpsURLConn.setHostnameVerifier(hv);
		httpsURLConn.setSSLSocketFactory(socketFactory);
		urlConn.setRequestProperty("test.uname", "uname");
		urlConn.setRequestProperty("test.pwd", "pwd");

		String encoding = urlConn.getContentEncoding();
		InputStream is = urlConn.getInputStream();
		InputStreamReader streamReader = new InputStreamReader(is, encoding != null ? encoding : "UTF-8");

		JSONParser parser = new JSONParser();
		JSONObject spUserAttributes = (JSONObject)parser.parse(streamReader);
		
		String resutl = (String) spUserAttributes.get("test");

		System.out.println(resutl);
	}
}