package dSikMandatoryProgramming;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private BigInteger e = new BigInteger("3");
	private BigInteger d, n = null;
	private BigInteger zero = BigInteger.ZERO;
	private BigInteger one = BigInteger.ONE;

	public static void main(String[] args) {
		RSA rsa = new RSA(2000);
		BigInteger message = new BigInteger("99999999999999999999999999");
		System.out.println("message: " + message);
		System.out.println("bitlength of message: " + message.bitLength());
		// encrypt and decrypt the message
		rsa.decrypt(rsa.encrypt(message));
	}

	public RSA(int k) {
		this.keyGen(k);
	}

	public BigInteger decrypt(BigInteger c) {
		// c^d mod n
		BigInteger decrypted = c.modPow(d, n);
		System.out.println("decrypted msg: " + decrypted);
		return decrypted;
	}

	// 0 <= numToEncrypt <= n-1
	public BigInteger encrypt(BigInteger m) {
		// c = m^e mod n
		BigInteger c = m.modPow(e, n);
		System.out.println("encrypted msg: " + c);
		return c;
	}

	/**
	 * @precondition: k >= 2000
	 */
	private void keyGen(int k) {
		int bitLengthOfQ = k / 2;
		int bitLengthOfP = k - bitLengthOfQ;

		BigInteger q;
		BigInteger p;
		BigInteger qMinusOne;
		BigInteger pMinusOne;
		boolean correctBitLength;
		boolean isInvertible;

		// bitlength of n should equal k
		do {
			q = rsaPrime(bitLengthOfQ);
			p = rsaPrime(bitLengthOfP);
			qMinusOne = q.subtract(one);
			pMinusOne = p.subtract(one);
			isInvertible = qMinusOne.multiply(pMinusOne).mod(e).equals(zero);
			
			n = p.multiply(q);
			correctBitLength = n.bitLength() == k;
		} while (!correctBitLength  || isInvertible);

		// d = e^{-1} mod (p-1)(q-1)
		d = e.modInverse(qMinusOne.multiply(pMinusOne));
	}
	
	private BigInteger rsaPrime(int bitLength) {
		BigInteger prime;
		SecureRandom random = new SecureRandom();
		do {
			prime = new BigInteger(bitLength, 100, random);
		} while (!(prime.subtract(one)).gcd(e).equals(one));
		return prime;
	}
}