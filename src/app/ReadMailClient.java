package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;
import kesystore.KeyStoreReader;
import model.mailclient.MailBody;
import signature.SignatureManager;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static String USERB_PATH = "./data/userb.jks";
	private static String userbPass = "cicacica";
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	    
		//Preuzimanje privatnog kljuca korisnika B
		char[] pass = userbPass.toCharArray();
		KeyStore keystore = KeyStoreReader.readKeyStore(USERB_PATH, pass);
		PrivateKey recieverPrivateKey = KeyStoreReader.getPrivateKeyFromKeyStore(keystore, "pera", pass);	
		
		//Preuzimanje javnog kljuca korisnika A iz njegovog sertifikata koji se nalazi u keystoru korisnika B
		Certificate certifiacateSender = KeyStoreReader.getCertificateFromKeyStore(keystore, "brvj");
		PublicKey senderPublicKey = KeyStoreReader.getPublicKeyFromCertificate(certifiacateSender);
				
		// Sifrovana poruka
		String textMail = MailHelper.getText(chosenMessage);
		
		// izdvojeni delovi mailbody
		MailBody mailBody = new MailBody(textMail);		
		String textMessage = mailBody.getEncMessage();
		
		byte[] iv1 = Base64.decode(mailBody.getIV1());
		byte[] iv2 = Base64.decode(mailBody.getIV2());
		byte[] sessionKeyEnc = Base64.decode(mailBody.getEncKey());

		
		//RSA init
		Security.addProvider(new BouncyCastleProvider());
		Cipher decypherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");		
		decypherRSA.init(Cipher.DECRYPT_MODE, recieverPrivateKey);
				
		byte [] sessionKey = decypherRSA.doFinal(sessionKeyEnc);
			
		//Decrypt a message and decompress it.
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey secretKey = new SecretKeySpec(sessionKey, "AES");
		
		IvParameterSpec ivParameterSpec1 = new IvParameterSpec(iv1);
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
			
		byte[] bodyEnc = Base64.decode(textMessage);
		String receivedBodyTxt = new String(aesCipherDec.doFinal(bodyEnc));
		String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
		
		
		//inicijalizacija za dekriptovanje
		IvParameterSpec ivParameterSpec2 = new IvParameterSpec(iv2);		
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
		
		//dekompresovanje i dekriptovanje subject-a
		String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
		
		//Provera potpisa
		SignatureManager signatureManager = new SignatureManager();
		if(signatureManager.verify(mailBody.getEncMessageBytes(),mailBody.getSignature().getBytes() , senderPublicKey)) {
			System.out.println("Signature is verified\n");
		}else {
			System.out.println("Signature is not verified\n");
		}
				
		System.out.println("Subject text: " + new String(decompressedSubjectTxt));
		System.out.println("Body text: " + decompressedBodyText);
								
	}
}
