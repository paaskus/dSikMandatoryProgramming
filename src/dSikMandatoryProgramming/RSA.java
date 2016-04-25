package dSikMandatoryProgramming;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private static final BigInteger e = new BigInteger("3");
	private BigInteger d;
	private BigInteger n = null;
	
	public static void main(String[] args) {
		RSA rsa = new RSA(100);
		BigInteger message = new BigInteger("100");
		System.out.println("message: "+message);
		System.out.println("bitlength of message: "+message.bitLength());
		// encrypt and decrypt the message
		rsa.decrypt(rsa.encrypt(message));
	}
	
	public RSA(int k) {
		this.keyGen(k);
	}
	
	public BigInteger decrypt (BigInteger c) {
		// c^d mod n
		BigInteger decrypted = c.modPow(d, n);
		System.out.println("decrypted msg: "+decrypted);
		return decrypted;
	}
	
	// 0 <= numToEncrypt <= n-1
	public BigInteger encrypt (BigInteger m) {
		// c = m^e mod n
		BigInteger c = m.modPow(e, n);
		System.out.println("encrypted msg: "+c);
		return c;
	}
	
	/**
	 * @precondition: k >= 2000
	 */
	private void keyGen (int k) {
		SecureRandom random = new SecureRandom();
		
		int max = k/2+k/10;
		int min = k/2-k/10;
		int bitLengthOfP = random.nextInt(max - min + 1) + min;
		int bitLengthOfQ = k - bitLengthOfP;
		System.out.println("bitlength of q: "+bitLengthOfQ);
		System.out.println("bitlength of p: "+bitLengthOfP);
		
		BigInteger p = new BigInteger(bitLengthOfP, random);
		BigInteger q = new BigInteger(bitLengthOfQ, random);

		// bitlength of n should equal k
		while ((n = p.multiply(q)).bitLength() != k) {
			// ensure that gcd(q-1, e) == 1
			do {
				q = new BigInteger(bitLengthOfQ, random);
			} while (!(q.subtract(BigInteger.ONE)).gcd(e).equals(BigInteger.ONE));
			
			// ensure that gcd(p-1, e) == 1
			do {
				p = new BigInteger(bitLengthOfP, random);
			} while (!(p.subtract(BigInteger.ONE)).gcd(e).equals(BigInteger.ONE));
			
			// n = p*q
			n = p.multiply(q);
		}
		System.out.println("q: "+q);
		System.out.println("p: "+p);
		System.out.println("n: "+n);
		
		// d = e^{-1} mod (p-1)(q-1)
		BigInteger qMinusOne = q.subtract(BigInteger.ONE); System.out.println("qMinusOne: "+qMinusOne);
		BigInteger pMinusOne = p.subtract(BigInteger.ONE); System.out.println("pMinusOne: "+pMinusOne);
		BigInteger phiOfN = pMinusOne.multiply(qMinusOne);
		d = e.modInverse(phiOfN);
		System.out.println("d: "+d);
	}
}