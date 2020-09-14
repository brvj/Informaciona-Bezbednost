package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.google.api.services.gmail.Gmail;
import kesystore.KeyStoreReader;
import model.mailclient.MailBody;
import signature.SignatureManager;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {	
	
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static SignatureManager signatureManager = new SignatureManager();
	
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
            
            MimeMessage message = message(reciever, subject, body);
			      	
        	MailWritter.sendMessage(service, "me", message);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
	
	
	private static MimeMessage message(String reciever, String subject, String body) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, MessagingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
			
		//Preuzimanje privatnog kljuca korisnka A(posiljaoca) iz njegovog keystora
		char[] pass = useraPass.toCharArray();
		KeyStore keystore = KeyStoreReader.readKeyStore(USERA_PATH, pass);			
		PrivateKey senderPrivateKey = KeyStoreReader.getPrivateKeyFromKeyStore(keystore, "brvj", pass);
		Certificate certifiacateSender = KeyStoreReader.getCertificateFromKeyStore(keystore, "brvj");
		PublicKey senderPublicKey = KeyStoreReader.getPublicKeyFromCertificate(certifiacateSender);
		
		//Preuzimanje javnog kljuca korisnika B iz njegovog sertifikata koji se nalazi u keystoru korisnika A
		Certificate certifiacateReceiver = KeyStoreReader.getCertificateFromKeyStore(keystore, "pera");
		PublicKey recieverPublicKey = KeyStoreReader.getPublicKeyFromCertificate(certifiacateReceiver);
				
		//Kompresuju se tema i tekst poruke
        String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
        String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
                      
        //Key generation
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
		SecretKey secretKey = keyGen.generateKey(); 
		Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		//inicijalizacija za sifrovanje 
		IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
				
		//sifrovanje teksta uz pomoc prethodno kreiranog iv1
		byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());

		//Potpisivanje poruke
        byte [] signature = signatureManager.sign(ciphertext, senderPrivateKey);
        
        //Provera potpisa
        boolean statusPotpisa = signatureManager.verify(ciphertext, signature, senderPublicKey);
        System.out.println("\nStatus potpisa -----> " + statusPotpisa);
		//System.out.println("Kriptovan tekst: " + ciphertextStr);
		
		//inicijalizacija za sifrovanje 
		IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
		
		//sifrovanje teme
		byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
		String ciphersubjectStr = Base64.encodeToString(ciphersubject);
		//System.out.println("Kriptovan subject: " + ciphersubjectStr);
		
		//RSA inicijalizacija
		Security.addProvider(new BouncyCastleProvider());
		Cipher cypherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");

		cypherRSA.init(Cipher.ENCRYPT_MODE, recieverPublicKey);
		
		//sifrovanje tajnog kljuca sa javnjim kljucem korisnika B		
		byte [] cypherSessionKey = cypherRSA.doFinal(secretKey.getEncoded());
		
		//Kreiranje MailBody
		MailBody mailBody = new MailBody(ciphertext, ivParameterSpec1.getIV(), ivParameterSpec2.getIV(), cypherSessionKey,signature);
		
		//Cuvanje IV i session kljuca // ne treba
//		JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
//		JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
//		JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
		
		//Pretvaranje mail body u string
		String mailBodySTR = mailBody.toCSV();
		
		MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mailBodySTR);
				
		return mimeMessage;
	}

}
