package test;

import java.security.KeyStore;

import kesystore.KeyStoreReader;

public class Test {

	private static String USER_A_PATH = "./data/usera.jks";
	private static String passwordA = "cicacica";
	
	
	public static void main(String[] args) {
		
		char[] pass = passwordA.toCharArray();
		KeyStore keystore = KeyStoreReader.readKeyStore(USER_A_PATH, pass);
		System.out.println(keystore);
		
	}

}
