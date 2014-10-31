package io.authentication.main;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class CertificateTwoMain {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {

		final String storeFile = "/usr/local/temp/test.crt";

		File file = new File(storeFile);
		InputStream caInput = new BufferedInputStream(new FileInputStream(file));
		CertificateFactory cf = CertificateFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

		Certificate ca;
		try {
		    ca = cf.generateCertificate(caInput);
		    System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
		} finally {
		    caInput.close();
		}
		// Create a KeyStore containing our trusted CAs
		String keyStoreType = KeyStore.getDefaultType();
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(null);
		keyStore.setCertificateEntry("ca", ca);

		// Create a TrustManager that trusts the CAs in our KeyStore
		String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
		tmf.init(keyStore);

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

	}
}