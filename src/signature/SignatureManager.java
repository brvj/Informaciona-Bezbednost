package signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureManager {
	
	public byte[] sign(byte[] data, PrivateKey privateKey) {
		try {
			// kreiramo objekat za potpisivanje
			// parametar getInstance metode je algoritam koji se koristi za potpisivanje. Na primer. vrednost moze biti i "SHA1withDSA"
			// voditi racuna da se koristi algoritam za potpisivanje i za proveru potpisa!
			Signature signature = Signature.getInstance("SHA1withRSA");
			
			// inicijalizacija privatnim kljucem - POTPISUJE SE PRIVATNIM KLJCEM!!!
			signature.initSign(privateKey);
			
			// postavljamo podatke koje potpisujemo
			signature.update(data);

			// vrsimo potpisivanje
			return signature.sign();
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	/**
	 * Metoda za verifikaciju digitalnog potpisa.
	 * 
	 * @param data - originalni podaci
	 * @param digitalSignature - digitalni potpis podataka
	 * @param publicKey - javni kljuc sa kojim se vrsi provera digitalnog potpisa
	 * 
	 * @return Boolean vrednost koja oznacava da li je digitalni potpis validan, odnosno da podaci nisu u medjuvremenu menjani
	 * 
	 * NAPOMENA: metoda ce vratiti true samo ukoliko originalni podaci nisu menjanu i ukoliko se za verifikaciju koristi javni kljuc
	 * koji je par sa privatnim kljucem sa kojim su podaci potpisani ž
	 */
	public boolean verify(byte[] data, byte[] digitalSignature, PublicKey publicKey) {
		try {
			// kreiramo objekat za potpisivanje
			// parametar getInstance metode je algoritam koji se koristi za potpisivanje. Na primer. vrednost moze biti i "SHA1withDSA"
			// voditi racuna da se koristi algoritam za potpisivanje i za proveru potpisa!
			Signature signature = Signature.getInstance("SHA1withRSA");
						
			// inicijalizacija privatnim kljucem - POTPIS SE VERIFIKUJE JAVNIM KLJUCEM!!!
			signature.initVerify(publicKey);
			
			// postavljamo podatke koje potpisujemo
			signature.update(data);

			// vrsimo proveru potpisa
			return signature.verify(digitalSignature);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			//e.printStackTrace();
		}
		
		return false;
	}
}
