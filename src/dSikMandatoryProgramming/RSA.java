package dSikMandatoryProgramming;

import java.math.BigInteger;
import java.util.Random;

public class RSA {
	private static final BigInteger e = new BigInteger("3");
	private BigInteger d;
	private BigInteger n = null;
	
	public static void main(String[] args) {
		RSA rsa = new RSA();
		rsa.keyGen(16);
		System.out.println("n = "+rsa.getN());
		BigInteger message = new BigInteger("100");
		System.out.println("Message: "+message);
		BigInteger encryptedMessage = rsa.encrypt(message);
		System.out.println("Encrypted message: "+encryptedMessage);
		BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
		System.out.println("Decrypted message: "+decryptedMessage);
	}
	
	public BigInteger decrypt (BigInteger numToDecrypt) {
		BigInteger decrypted = numToDecrypt.modPow(d, n);
		return decrypted;
	}
	
	public BigInteger encrypt (BigInteger numToEncrypt) {
		BigInteger encrypted = numToEncrypt.modPow(e, n);
		return encrypted;
	}
	
	/**
	 * @precondition: k >= 8
	 */
	public void keyGen (int k) {
		Random random = new Random();
		
		int max = k/2+k/10;
		int min = k/2-k/10;
		int bitLengthOfP = random.nextInt(max - min + 1) + min;
		int bitLengthOfQ = k - bitLengthOfP;
		
		BigInteger p = new BigInteger(bitLengthOfP, random);
		BigInteger q = new BigInteger(bitLengthOfQ, random);
		BigInteger one = new BigInteger("1");

		while ((n = p.multiply(q)).bitLength() != k) {
			q = new BigInteger(bitLengthOfQ, random);
			while(!(q.subtract(one)).gcd(e).equals(one)) {
				q = new BigInteger(bitLengthOfQ, random);
			}
			p = new BigInteger(bitLengthOfP, random);
			while(!(p.subtract(one)).gcd(e).equals(one)) {
				p = new BigInteger(bitLengthOfP, random);
			}
			n = p.multiply(q);
		}
		BigInteger phiOfN = p.subtract(one).multiply(q.subtract(one));
		d = e.modInverse(phiOfN);
		System.out.println("Benny: "+d.multiply(e).mod(phiOfN));
	}
	
	public BigInteger getN() {
		return n;
	}
}
