package com.nilshonermann.StudiumTools.verteiltesysteme;

import java.awt.Point;
import java.util.ArrayList;
import java.util.Stack;

/**
 * 
 * @author Nils Honermann
 * 
 * <b>Dieses Programm soll dazu dienen "schlecht gewählte b.z.w. kleine bis mittlgroße primzahlen p,q" bei kleinem n raum zu extrahieren</b>
 * <br>
 * <b>- RSAZerlegung.primzahlzerlegungKleinePQwithN(int)(...):</b> zu gegebenen n soll ein passendes p,q gefunden werden
 * <br>
 * <b>- RSAZerlegung.primzahlzerlegungKleinePQwithNANDZ(int, int, boolean)(int)(...):</b> zu gegebenen n,z soll ein passendes p,q gefunden werden
 * <br>
 * <b>- RSAZerlegung.berechneZdurchPQ(int, int)(...):</b> aus p,q soll z berechnet werden
 * <br>
 * <b>- RSAZerlegung.berechneDzuGegebenenE(int, int)(...):</b> aus z,e soll ein d berechnet werden
 * <br>
 * <b>- RSAZerlegung.berechneEDwobeiEimAngegebenenBereichSeinMuss(...):</b> aus z und e in range soll ein d berechnet werden
 * <br>
 * <b>- RSAZerlegung.encrypt(...):</b> zu gegebenen e,n soll eine nachricht m verschlüsselt werden
 * <br>
 * <b>- RSAZerlegung.decrypt(...):</b> zu gegebenen d,n soll ein geheimtext c entschlüsselt werden
 * <p>
 * Das RSA Cryptosystem funktioniert wie folgt:
 * <br>
 * - zwei zufällige Primzahlen p,q, wählen
 * <br>
 * - berechne n=p*q 
 * <br>
 * - berechne phi(n)=z=(p-1)*(q-1) 
 * <br>
 * - wähle zwei zahlen e,d die teilerfremd zu z sind, sodass (e*d)mod z = 1 erfüllt ist
 * <br>
 * === Das Schlüsselpaar besteht aus öffentlicher Teil [e,n] privater Teil [d,n] ===
 * <br>
 * - um eine Nachricht m zu verschlüsseln berechne den Ciphertext c = m^e mod n wobei m<n gelten muss
 * <br>
 * - um einen Ciphertext wieder zu entschlüsseln berechne die Ursprungsnachricht m = c^d mod n
 * <br>
 * (die spezielle struktur von u^v mod w erlaubt rechenregeln um zahlen stark zu kürzen womit man i.A. im int Bereich bleiben kann)
 * <br>
 * <p>
 * + Vertraulichkeit (encryption, confidentiality) := Nachricht von Alice an Bob senden, Alice verschlüsselt mit öffentlichem Schlüssel von Bob, nur Bob kann mit seinem privatem Schlüssel entschlüsseln
 * <br>
 * + Signatur (sign, non-repudiation) := RSA Schlüssel tauschen die Rolle, Alice signiert ihre Nachricht indem Sie die Nachricht(+Prüfsumme) mit Ihrem privatem Teil verschlüsselt, jeder kann mit öffentlichem Teil von Alice entschlüsseln und die Prüfsumme garantiert dass die Nachricht wirklich von Alice stammt (und unverändert ist). Dabei muss ein eigenes Schlüsselpaar verwendet werden! Nicht das selbe wie zum RSA-Vertaulichverschlüsseln!!!
 */
public class RSAZerlegung {
	private static int[] primeList1000_without1 = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, /**/
			101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, /**/
			211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, /**/
			307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, /**/
			401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, /**/
			503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, /**/
			601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, /**/
			701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, /**/
			809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, /**/
			907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997 /*... list is capped at 1000 */
			};
	
	
	public static void main(String[] args) {
		System.out.println("\t\t\t\t RSA Zerlegung");
		System.out.println("---------------------------------------------------------------------------------------------------------");
		
		/**
		 * hier werte und funktionen eintragen zum lösen der aufgaben :)
		 */
		int n = 7387;
		System.out.println("\t\t\t\t\t\t\t\t N="+n);
		Point pq = primzahlzerlegungKleinePQwithN(n); // <------- diese nutzen wenn irgendeine aufteilung von p,q die zu n passen muss
		// Point pq = instance.primzahlzerlegungKleinePQwithNANDZ(n,z); // <------- diese nutzen wenn aufteilung p,q sowohl zu n als auch zu z passen muss
		System.out.println("\t\t\t\t\t\t\t\t P="+pq.x);
		System.out.println("\t\t\t\t\t\t\t\t Q="+pq.y);
		/**
		 * 
		 */
		int z = berechneZdurchPQ(pq.x, pq.y); // berechnen oder weiter oben eintragen fix
		System.out.println("\t\t\t\t\t\t\t\t Z="+z);
		/**
		 * 
		 */
		int startFromE=50; // <----------- wenn e,d beide unbekannt und e in einem konkreten bereich sein soll passend (eine möglichkeit) ermitteln 
		int upToE=59;
		Point ed = berechneEDwobeiEimAngegebenenBereichSeinMuss(startFromE,upToE,z);
		System.out.println("\t\t\t\t\t\t\t\t E="+ed.x);
		System.out.println("\t\t\t\t\t\t\t\t D="+ed.y);
		//int e=50; // <--------------- wenn von e,d einer der beiden bekannt ist den anderen passend (eine möglichkeit) ermitteln
		//int d=instance.berechneDzuGegebenenE_V2(tryMeE,z); // wähleEundD_wobeiEbekannt(tryMeE, z);
		
		/**
		 * 
		 */
		System.err.println("---------------------------------------------------------------------------------------------------------");
		System.err.println("\tEncryp/decryp klappt nur bei kleinen Zahlen (m,c,e,d)!!! \n\tAnsonsten Besser Zerlegung Per Hand wegen OutOfBounds wird verschluckt und gibt falsche Ergebnisse!!!");
		System.err.println("---------------------------------------------------------------------------------------------------------");
		int m = 2021; // oder text chars erst in blöcke und von asci zu int konvertieren; blockgröße es muss gelten m<=n
		
		
		//n=51;
		//m=40;
		//ed.x=7;
		//ed.y=23;
		
		
		int c_ipher = encrypt(m,ed.x,n);
		System.out.println("\t\t\t\t\t\t\t\t C=encrypt(m)="+c_ipher);
		int c_ipher2 = c_ipher;
		int m_original2 = decrypt(c_ipher2, ed.y,n);
		System.out.println("\t\t\t\t\t\t\t\t M2=decrypt(c2)="+m_original2);
		
		System.out.println("---------------------------------------------------------------------------------------------------------");
	}
	
	public static int encrypt(int m, int e, int n) {
		if(m>n) {
			System.err.println("BEDINGUNG BLOCKGRÖ?E VERLETZT! ES MUSS m<=n GELTEN!");
			return -1;
		}
		else {
			double result = calculate_A_timespow_B_modulo_C(m,e,n);//((Math.pow(m, e)) % n);
			System.out.println("Verschlüsselter Wert: \t c = m^e mod n = " +m+"^"+e+ " mod " +n+ " \t\t =" + result);
			return (int)result;
		}
	}
	
	public static int decrypt(int c_ipher, int d, int n) {
		int result =  calculate_A_timespow_B_modulo_C(c_ipher,d,n);//((Math.pow(c_ipher, d)) % n); // same operation as encrypt but without the blocksize check, since cipher is already c=m^e this c^d=m^e^d will return back to =m under %n
		System.out.println("Entschlüsselter Wert: \t m = c^d mod n = " + c_ipher+"^"+d + " mod " + n +" \t =" + result);
		return result;
	}
	
	/**
	 * klappt nur für Aufgaben in der Form (a^b modulo c) beziehungsweise für ((Math.pow(a, b)) % c)
	 * <br>
	 * nutzt mathe rechenregel um modulo wert aufzutrennen und  zu verkleinern
	 * <br>
	 * 2^4 = 2*2*2*2 = 2^2 * 2^2 = 2^(2+2) 
	 * <br>
	 * (x*y) mod z = [(x mod z)*(y mod z)]mod z
	 * <br>
	 * außeinander gezogen und wieder zusammengeführt gilt: ist x mod z = w dann ist (x*y)mod z = (w*y)mod z
	 * 
	 * @return
	 */
	private static int calculate_A_timespow_B_modulo_C(int a, int b, int c) {
		if(b<1 || a<1 || c<1) {
			System.err.println("a^b mod c kann (hier) nur mit ganzen POSITIVEN zahlen berechnet werden. ("+a+"^"+b+")mod "+c+" FEHLER -1");
			return -1;
		}
		
		if(a>c) {
			a = a%c; // alle a einzeln ziehen und schrumpfen
		}
		
		ArrayList<Long> factorList = new ArrayList<>();
		for(int i=0;i<b;i++) {
			factorList.add((long) a);
		}
		
		while(factorList.size()>=2) {
			// stück für stück alle faktoren zusammenziehen und immer wieder zu mod c minimieren bis nur noch ein wert => ergebnis
			long one = factorList.get(0); // get values from the left side
			long two = factorList.get(1);
			factorList.remove(1); // remove values from the left side, remove 1 before 0 (or two times 0)
			factorList.remove(0);
			long oneTwoProd = one*two; // calculate product
			if(oneTwoProd>c) {
				oneTwoProd=oneTwoProd%c; // reduce by modulo if possible
			}
			factorList.add(oneTwoProd); // append (reduced) factor product to the right side
		}
		
		int result = factorList.get(0).intValue(); 
		return result;
	}
	
	public static int berechneZdurchPQ(int p, int q) {
		return (p-1)*(q-1);
	}
	
	/**
	 * 
	 * @param startFromE - von hier wird begonnen zu versuchen
	 * @param upToE - bis hier wird versucht. ist upToE größer als startFromE wird hochgezählt. andernfalls runtergezählt!
	 */
	public static Point berechneEDwobeiEimAngegebenenBereichSeinMuss(int startFromE, int upToE, int z) {
		Point ed = new Point();
		ed.x=-1;
		ed.y=-1;
		boolean countUp=true;
		if(upToE<startFromE) {
			countUp=false;
			System.out.println("Suche e,d passend zu z("+z+") wobei e,d unbekannt aber e im Bereich von ["+startFromE+","+upToE+"] (runterzählend, finde größtes e)");
		}
		else {
			System.out.println("Suche e,d passend zu z("+z+") wobei e,d unbekannt aber e im Bereich von ["+startFromE+","+upToE+"] (hochzählend, finde kleinstes e)");
		}
		
		int updowncounter=0;
		boolean found=false;
		final boolean stoppOnFound=true;
		while(!found && updowncounter<=positivInt(startFromE-upToE)) {
			int tryMeE = startFromE+updowncounter;
			
			//
			
			int d = berechneDzuGegebenenE_V2(tryMeE,z); // schneller Ansatz wenn e schon super passt, ist glaube ich fehlerhaft wenn e nicht teilerfremd ausfällt
			if(d!=-1) {
				ed.x=tryMeE;
				ed.y=d;
				found=stoppOnFound&&true;
			}
			else {
				d = berechneDzuGegebenenE(tryMeE, z); // langsamerer Ansatz, ist glaube Ich Fehlerhaft wenn e oder d > n ausfallen
				if(d!=-1) {
					ed.x=tryMeE;
					ed.y=d;
					found=stoppOnFound&&true;
				}
			}
			
			//
			
			if(countUp) {
				updowncounter++;
			}
			else {
				updowncounter--;
			}
		}
		return ed;
	}
	
	/**
	 * klappt nur bei kleinen zahlen, sonst schlecht
	 * @param e
	 * @param z
	 * @return
	 */
	public static int berechneDzuGegebenenE(int e,int z) {
		int x = 1;
		int MAX_X=100;
		boolean found = false;
		// e*d mod z = 1
		// ----> (z*x+1)/e=D' und wenn D' ganze Zahl ist d=D'
		int d_result = -1;
		while(!found && x<MAX_X) {
			if((z*x+1)%e==0) {
				// ganze zahl test mit modulo ok
				int d = (z*x+1)/e;
				// nochmal testen ob gleichung in andere richtung erfüllt ist
				if( (e*d-1)%z==0 /*&& d<z*/) {														// größer ist erlaubt, hauptsache teilerfremd?
					// ok
					System.out.println("Ein mögliches d' zu gegebenem e("+e+") ist d'=" + d);
					found = true;
					d_result = d;
					
				}
				/*else if(d>=z) {
					System.out.println("... d'("+d+") ist bereits größer als z, skip/break!"); // else skip!
					break;
				}*/
				else {
					System.out.println("... d'("+d+") ist ein false positive, skip!"); // else skip!
				}
				
			}
			x++;
		}
		if(d_result==-1) {
			System.out.println("Konnte kein passendes d zu angegebenen e("+e+") finden nach "+ x + " versuchen.");
		}
		else {
			System.out.println("Mögliche Aufteilung zu dem gegebenen z("+z+") lautet: \t\t (e,d) = ("+e+","+d_result+")");
		}
		return d_result;
	}
	
	public static Point primzahlzerlegungKleinePQwithN(int n) {
		return primzahlzerlegungKleinePQwithNANDZ(n,0,false);
	}
	
	public static Point primzahlzerlegungKleinePQwithNANDZ(int n, int z) {
		return primzahlzerlegungKleinePQwithNANDZ(n,z,true);
	}
	private static Point primzahlzerlegungKleinePQwithNANDZ(int n, int z, boolean checkZ) {
		Point pq = new Point();
		pq.x=-1;
		pq.y=-1;
		if(intArrayContains(primeList1000_without1,n)) {
			if(checkZ && z==berechneZdurchPQ(n, 1)) {
				System.out.println("N IS ALREADY A PRIME n=p*q can be splitted as following: \t\t\t\t " +n+ " = " + n + " * " + 1);
				pq.x=n;
				pq.y=1;
			}
			if(!checkZ) {
				System.out.println("N IS ALREADY A PRIME n=p*q can be splitted as following: \t\t\t\t " +n+ " = " + n + " * " + 1);
				pq.x=n;
				pq.y=1;
			}
		}
		
		for(int tryMeP : primeList1000_without1) {
			if(n % tryMeP == 0) {
				// division ergibt ganze zahl ohne rest prüfen
				int tryMeE = n/tryMeP; // mögliches e berechnen
				if(intArrayContains(primeList1000_without1,tryMeE)) {
					// tryMeP and tryMeE are within the prime list => use this as the result!
					if(checkZ && z==berechneZdurchPQ(tryMeP, tryMeE)) {
						System.out.println("n=p*q can be splitted as following: \t\t\t\t " +n+ " = " + tryMeP + " * " + tryMeE);
						pq.x=tryMeP;
						pq.y=tryMeE;
					}
					if(!checkZ) {
						System.out.println("n=p*q can be splitted as following: \t\t\t\t " +n+ " = " + tryMeP + " * " + tryMeE);
						pq.x=tryMeP;
						pq.y=tryMeE;
					}
				}
			}
		}
		return pq;
	}
	
	@Deprecated
	public static int berechneDzuGegebenenE_V2(int e, int p, int q) {
		return berechneDzuGegebenenE_V2(e,berechneZdurchPQ(p, q));
	}
	
	@Deprecated
	public static int berechneDzuGegebenenE_V2(int e, int z) {
		int d = (1+ z )/e;
		// nochmal testen ob gleichung in andere richtung erfüllt ist
		if( (e*d)%z==1 ) {
			// ok
			System.out.println("Ein mögliches d' zu gegebenem e("+e+") ist d'=" + d);
			return d;
		}
		// else false positive, skip!
		else {
			System.out.println("...Falsches d'... meeh");
			return -1;
		}
	}

	
	private static int positivInt(int i) {
		if(i<0)return i*-1;
		return i;
	}
	
	private static boolean intArrayContains(int[] array, int contains) {
		for(int i : array) {
			if(i==contains) {
				return true;
			}
		}
		return false;
	}

}
