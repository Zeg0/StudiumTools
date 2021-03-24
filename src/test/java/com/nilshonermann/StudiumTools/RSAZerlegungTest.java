package com.nilshonermann.StudiumTools;

import org.junit.*;

import com.nilshonermann.StudiumTools.verteiltesysteme.RSAZerlegung;

import static org.junit.Assert.*;

import java.awt.Point;

/**
 * 
 * @author Nils Honermann
 *
 */
public class RSAZerlegungTest {
	
	@Test
	public void testHolePQvonN_a() {
		int n = 33;
		int expectedP = 11;
		int expectedQ = 3;
		Point pq = RSAZerlegung.primzahlzerlegungKleinePQwithN(n);
		assertEquals("Anderes p erwartet",expectedP, pq.x);
		assertEquals("Anderes q erwartet",expectedQ ,pq.y);
	}
	
	@Test
	public void testHolePQvonN_b() {
		int n = 51;
		int expectedP = 17;
		int expectedQ = 3;
		Point pq = RSAZerlegung.primzahlzerlegungKleinePQwithN(n);
		assertEquals("Anderes p erwartet",expectedP, pq.x);
		assertEquals("Anderes q erwartet",expectedQ ,pq.y);
	}
	
	@Test
	public void testHolePQvonN_LargeC() {
		int n = 7387;
		int expectedP = 89;
		int expectedQ = 83;
		Point pq = RSAZerlegung.primzahlzerlegungKleinePQwithN(n);
		assertEquals("Anderes p erwartet",expectedP, pq.x);
		assertEquals("Anderes q erwartet",expectedQ ,pq.y);
	}
	
	@Test
	public void testHolePQvonN_LargeD() {
		int n = 10807;
		int expectedP = 107;
		int expectedQ = 101;
		Point pq = RSAZerlegung.primzahlzerlegungKleinePQwithN(n);
		assertEquals("Anderes p erwartet",expectedP, pq.x);
		assertEquals("Anderes q erwartet",expectedQ ,pq.y);
	}
	
	@Test
	public void testBerechneZausPQundBerechneDbeiAngegebenenE_a() {
		int n = 51;
		int p = 17;
		int q = 3;
		int givenE = 7;
		int expectedZ = 32;
		int expectedD = 23;
		int z = RSAZerlegung.berechneZdurchPQ(p, q);
		assertEquals("Anderes z erwartet", expectedZ, z);
		int d = RSAZerlegung.berechneDzuGegebenenE/*berechneDzuGegebenenE_V2*/(givenE, z);
		assertEquals("Anderes d erwartet", expectedD, d);
	}
	
	@Test
	public void testBerechneZausPQundBerechneDbeiAngegebenenE_b() {
		int n = 33;
		int p = 3;
		int q = 11;
		int givenE = 3;
		int expectedZ = 20;
		int expectedD = 7;
		int z = RSAZerlegung.berechneZdurchPQ(p, q);
		assertEquals("Anderes z erwartet", expectedZ, z);
		int d = RSAZerlegung.berechneDzuGegebenenE/*berechneDzuGegebenenE_V2*/(givenE, z);
		assertEquals("Anderes d erwartet", expectedD, d);
	}
	
	@Test
	public void testBerechneZausPQundBerechneDbeiUnbekanntemE_LargeC() {
		int n = 7387;
		int p = 89;
		int q = 83;
		int expectedZ = 7216;
		int z = RSAZerlegung.berechneZdurchPQ(p, q);
		assertEquals("Anderes z erwartet", expectedZ, z);
		int rangeEFrom = 50;
		int rangeETo = 59;
		int expectedLowEWithinRange = 51;
		int expectedD = 283;
		Point ed = RSAZerlegung.berechneEDwobeiEimAngegebenenBereichSeinMuss(rangeEFrom, rangeETo, z);
		assertEquals("Anderes e erwartet", expectedLowEWithinRange, ed.x);
		assertEquals("Anderes d erwartet", expectedD, ed.y);
	}
	
	@Test
	public void testBerechneZausPQundBerechneDbeiUnbekanntemE_LargeD() {
		int n = 10807;
		int p = 107;
		int q = 101;
		int expectedZ = 10600;
		int z = RSAZerlegung.berechneZdurchPQ(p, q);
		assertEquals("Anderes z erwartet", expectedZ, z);
		int rangeEFrom = 5;
		int rangeETo = 99999;
		int expectedLowEWithinRange = 7;
		int expectedD = 4543;
		Point ed = RSAZerlegung.berechneEDwobeiEimAngegebenenBereichSeinMuss(rangeEFrom, rangeETo, z);
		assertEquals("Anderes e erwartet", expectedLowEWithinRange, ed.x);
		assertEquals("Anderes d erwartet", expectedD, ed.y);
	}

	
	@Test
	public void testEncryptDecrypt_a1() {
		int n = 33;
		int p = 3;
		int q = 11;
		int e = 3;
		int z = 20;
		int d = 7;
		int m = 16;
		int expectedC = 4;
		int c = RSAZerlegung.encrypt(m, e, n);
		assertEquals("Anderes c erwartet", expectedC, c);
		int m2 = RSAZerlegung.decrypt(c, d, n);
		assertEquals("Gleiches ursprüngliches m nach wieder entschlüsseln erwartet", m, m2);
	}
	
	@Test
	public void testEncryptDecrypt_a2() {
		int n = 33;
		int p = 3;
		int q = 11;
		int e = 3;
		int z = 20;
		int d = 7;
		int m = 2;
		int expectedC = 8;
		int c = RSAZerlegung.encrypt(m, e, n);
		assertEquals("Anderes c erwartet", expectedC, c);
		int m2 = RSAZerlegung.decrypt(c, d, n);
		assertEquals("Gleiches ursprüngliches m nach wieder entschlüsseln erwartet", m, m2);
	}
	
	@Test
	public void testEncryptDecrypt_b1() {
		int n = 51;
		int p = 17;
		int q = 3;
		int e = 7;
		int z = 32;
		int d = 23;
		int m = 4;
		int expectedC = 13;
		int c = RSAZerlegung.encrypt(m, e, n);
		assertEquals("Anderes c erwartet", expectedC, c);
		int m2 = RSAZerlegung.decrypt(c, d, n);
		assertEquals("Gleiches ursprüngliches m nach wieder entschlüsseln erwartet", m, m2);
	}
	
	@Test
	public void testEncryptDecrypt_b2() {
		int n = 51;
		int p = 17;
		int q = 3;
		int e = 7;
		int z = 32;
		int d = 23;
		int m = 26;
		int expectedC = 2;
		int c = RSAZerlegung.encrypt(m, e, n);
		assertEquals("Anderes c erwartet", expectedC, c);
		int m2 = RSAZerlegung.decrypt(c, d, n);
		assertEquals("Gleiches ursprüngliches m nach wieder entschlüsseln erwartet", m, m2);
	}
	
	@Test
	public void testEncryptDecrypt_LargeC1() {
		int n = 7387;
		int p = 89;
		int q = 83;
		int z = 7216;
		int e = 51;
		int d = 283;
		int m = 2021;
		int expectedC = 6422;
		int c = RSAZerlegung.encrypt(m, e, n);
		assertEquals("Anderes c erwartet", expectedC, c);
		int m2 = RSAZerlegung.decrypt(c, d, n);
		assertEquals("Gleiches ursprüngliches m nach wieder entschlüsseln erwartet", m, m2);
	}
	
	@Test
	public void testEncryptDecrypt_LargeC2() {
		int n = 7387;
		int p = 89;
		int q = 83;
		int z = 7216;
		int e = 51;
		int d = 283;
		int m = 7000;
		int c = RSAZerlegung.encrypt(m, e, n);
		// skip c check
		int m2 = RSAZerlegung.decrypt(c, d, n);
		assertEquals("Gleiches ursprüngliches m nach wieder entschlüsseln erwartet", m, m2);
	}
	
	@Test
	public void testEncryptDecrypt_LargeD() {
		int n = 10807;
		int p = 107;
		int q = 101;
		int z = 10600;
		int e = 7;
		int d = 4543;
		int m = 7000;
		int c = RSAZerlegung.encrypt(m, e, n);
		// skip c check
		int m2 = RSAZerlegung.decrypt(c, d, n);
		assertEquals("Gleiches ursprüngliches m nach wieder entschlüsseln erwartet", m, m2);
	}
	
}
