/**
 * 
 */
package com.venafi.vcert.sdk.connectors.cloud;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.bouncycastle.crypto.digests.Blake2bDigest;

import com.iwebpp.crypto.TweetNaclFast;


/**
 * The following utility is based on the SealBoxUtility code shared in the stackoverflow question
 * <a href="https://stackoverflow.com/questions/42456624/how-can-i-create-or-open-a-libsodium-compatible-sealed-box-in-pure-java">
 * How can I create or open a libsodium compatible sealed box in pure Java</a>.
 * <br/>
 * The main difference is on this version is being used the <a href="https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/digests/Blake2bDigest.java">
 *  org.bouncycastle.crypto.digests.Blake2bDigest</a> from <a href="https://github.com/bcgit/bc-java">The Bouncy Castle Crypto Package For Java</a> 
 *  instead of <a href="https://github.com/alphazero/Blake2b">Blake2b</a> to get the Blake2b hash.
 * <br/><br/>
 * 
 * Has also a dependency on TweetNaclFast from <a href="https://github.com/InstantWebP2P/tweetnacl-java">https://github.com/InstantWebP2P/tweetnacl-java</a>.
 * 
 * 
 */
public class SealedBoxUtility {


	public static final int CRYPTO_BOX_NONCEBYTES = 24;
	//public static final int crypto_box_PUBLICKEYBYTES = 32;
	//public static final int crypto_box_MACBYTES = 16;
	//public static final int crypto_box_SEALBYTES = (crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES);

	//  libsodium
	//  int crypto_box_seal(unsigned char *c, const unsigned char *m,
	//            unsigned long long mlen, const unsigned char *pk);
	/**
	 * Encrypt in  a sealed box
	 *
	 * @param receiverPubKey receiver public key
	 * @param clearText clear text
	 * @return encrypted message
	 * @throws GeneralSecurityException 
	 */
	public static byte[] cryptoBoxSeal(byte[] receiverPubKey, byte[] clearText) throws GeneralSecurityException {

		// create ephemeral keypair for sender
		TweetNaclFast.Box.KeyPair ephkeypair = TweetNaclFast.Box.keyPair();
		// create nonce
		byte[] nonce = cryptoBoxSealNonce(ephkeypair.getPublicKey(), receiverPubKey);
		TweetNaclFast.Box box = new TweetNaclFast.Box(receiverPubKey, ephkeypair.getSecretKey());
		byte[] ciphertext = box.box(clearText, nonce);
		if (ciphertext == null) 
			throw new GeneralSecurityException("Could not create the crypto box");
		
		byte[] sealedbox = null;
		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
			byteArrayOutputStream.write(ephkeypair.getPublicKey());
			byteArrayOutputStream.write(ciphertext);
			sealedbox = byteArrayOutputStream.toByteArray();
		} catch (IOException e) {
			throw new GeneralSecurityException("Could not create the sealed crypto box", e);
		}
		return sealedbox;
	}

	/**
	 *  hash the combination of senderpk + mypk into nonce using blake2b hash
	 * @param senderpk the senders public key
	 * @param mypk my own public key
	 * @return the nonce computed using Blake2b generic hash
	 */
	public static byte[] cryptoBoxSealNonce(byte[] senderpk, byte[] mypk){
		// C source ported from libsodium
		//      crypto_generichash_state st;
		//
		//      crypto_generichash_init(&st, NULL, 0U, CRYPTO_BOX_NONCEBYTES);
		//      crypto_generichash_update(&st, pk1, crypto_box_PUBLICKEYBYTES);
		//      crypto_generichash_update(&st, pk2, crypto_box_PUBLICKEYBYTES);
		//      crypto_generichash_final(&st, nonce, CRYPTO_BOX_NONCEBYTES);
		//
		//      return 0;
		final Blake2bDigest blake2b = new Blake2bDigest( CRYPTO_BOX_NONCEBYTES*8 ); 
		blake2b.update(senderpk, 0, senderpk.length);
		blake2b.update(mypk, 0, mypk.length);
		byte[] nonce = new byte[CRYPTO_BOX_NONCEBYTES];
		blake2b.doFinal(nonce, 0);
		if (nonce == null || nonce.length!=CRYPTO_BOX_NONCEBYTES) throw new IllegalArgumentException("Blake2b hashing failed");
		return nonce;
	}

}