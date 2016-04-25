package dSikMandatoryProgramming;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private BigInteger e = new BigInteger("3");
	private BigInteger d, n = null;
	private BigInteger zero = BigInteger.ZERO;
	private BigInteger one = BigInteger.ONE;

	public static void main(String[] args) {
		RSA rsa = new RSA(100);
		BigInteger message = new BigInteger("100");
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
		SecureRandom random = new SecureRandom();

		int bitLengthOfQ = k / 2;
		int bitLengthOfP = k - bitLengthOfQ;

		BigInteger q = new BigInteger(bitLengthOfQ, 100, random);
		BigInteger p = new BigInteger(bitLengthOfP, 100, random);

		// bitlength of n should equal k
		while ((n = p.multiply(q)).bitLength() != k  || q.subtract(one).multiply(p.subtract(one)).mod(e).equals(zero)) {
			// ensure that gcd(q-1, e) == 1
			do {
				q = new BigInteger(bitLengthOfQ, 100, random);
			} while (!(q.subtract(one)).gcd(e).equals(one));

			// ensure that gcd(p-1, e) == 1
			do {
				p = new BigInteger(bitLengthOfP, 100, random);
			} while (!(p.subtract(one)).gcd(e).equals(one));

			// n = p*q
			n = p.multiply(q);
		}
		
		System.out.println("bitlength of n: " + n.bitLength());

		System.out.println("q: " + q);
		System.out.println("p: " + p);
		System.out.println("n: " + n);

		// d = e^{-1} mod (p-1)(q-1)
		BigInteger qMinusOne = q.subtract(one);
		System.out.println("qMinusOne: " + qMinusOne);
		BigInteger pMinusOne = p.subtract(one);
		System.out.println("pMinusOne: " + pMinusOne);
		System.out.println("pq mod e: "+qMinusOne.multiply(pMinusOne).mod(e));
		d = e.modInverse(qMinusOne.multiply(pMinusOne));
	}
}