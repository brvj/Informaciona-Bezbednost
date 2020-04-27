package app;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.google.api.services.gmail.Gmail;

import kesystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {
	
	
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static String USERA_PATH = "./data/usera.jks";
	private static String useraPass = "cicacica";
	
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
        	
        	
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey(); //privatni session kljuc koji treba enkriptovati kljucem korisnika B RSA
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			
			//Pomoću klase KeyStoreReader iz usera.jks preuzeti sertifikat i javni ključ korisnika B
			char[] pass = useraPass.toCharArray();
			
			//Citanje fajla usera.jks
			KeyStore keystore = KeyStoreReader.readKeyStore(USERA_PATH, pass);
			
			//Preuzimanje sertifikata korisnika B iz usera.jks
			Certificate certificateB = KeyStoreReader.getCertificateFromKeyStore(keystore, "pera");
			//Preuzimanje javnog kljuca korisnika B
			PublicKey publicKeyB = KeyStoreReader.getPublicKeyFromCertificate(certificateB);
			Security.addProvider(new BouncyCastleProvider());
			Cipher cypherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
			cypherRSA.init(Cipher.ENCRYPT_MODE, publicKeyB);
			
			byte[] cypherSessionKey = cypherRSA.doFinal(secretKey.getEncoded());
			//public MailBody(String encMessage, String iV1, String iV2, String encKey)
			//pravljenje tela mail kako bih mogao da iskoristim toCSV koji vraca string koji treba zapravo da posaljem
			
			byte[] iv1byte = ivParameterSpec1.getIV();
			String IV1mail = Base64.encodeToString(iv1byte);
			
			byte[] iv2byte = ivParameterSpec2.getIV();
			String IV2mail = Base64.encodeToString(iv2byte);
			
			byte[] key = cypherSessionKey;
			String keyMail = Base64.encodeToString(key);
			
			MailBody mailBody = new MailBody(ciphertextStr, IV1mail, IV2mail, keyMail);
			
			String mailBodyStr = mailBody.toCSV();
					
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mailBodyStr);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
}
