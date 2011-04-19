package org.catacombae.hfsexplorer.iphone;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.catacombae.dmgextractor.Util;
import org.catacombae.hfsexplorer.io.ReadableRandomAccessSubstream;
import org.catacombae.hfsexplorer.io.SynchronizedReadableRandomAccess;
import org.catacombae.io.RuntimeIOException;

/**
 * blocksize is 0x1000 on iPad1,1 but 0x2000 on iPhone3,1
 * 
 *
 */
public class EMFRandomAccess extends ReadableRandomAccessSubstream {
	private byte[] fileKey;
	private int blockSize;
	private BufferedBlockCipher emf_encrypter;
	private BufferedBlockCipher filekey_decrypter;
	private KeyParameter fileKeyParam;
	private KeyParameter emfKeyParam;

	private int baseLBA;
	
	public EMFRandomAccess(SynchronizedReadableRandomAccess iSourceStream, byte[] key, long bSize) {
		super(iSourceStream);
		fileKey = key;
		blockSize = (int) bSize;
		emf_encrypter = new BufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
		filekey_decrypter = new BufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
		
		emfKeyParam = new KeyParameter(EMF.getInstance().getEMFKey());
		fileKeyParam = new KeyParameter(fileKey);
		baseLBA = EMF.getInstance().getBaseLBA();
	}
   
    @Override
    public int read(byte[] b, int pos, int len) throws RuntimeIOException {
    	int nblocks = len / blockSize;
    	int bytesRead = 0;
    	long lba = internalFP/blockSize;
    	int offset = (int) (internalFP % blockSize);
        long oldFP = getFilePointer();
    	long newFP = lba * blockSize;
    	seek(newFP);
    	
    	for(int i=0; i < nblocks; i++)
    	{
    		bytesRead += readBlock(lba, offset, b, bytesRead, blockSize - offset);
    		lba += 1;
    		offset = 0;
    	}
    	if ((len % blockSize) != 0)
    		bytesRead += readBlock(lba, 0, b, bytesRead, len % blockSize);
    	return bytesRead;
    }
    
    /**
     * Reencrypt data fork blocks with the EMF key and decrypt the result with 
     * the correct file key
     * @param lba
     * @param offset
     * @param b
     * @param boffset
     * @param len
     * @return
     */
    private int readBlock(long lba, int offset, byte[] b, int boffset, int len) {
        byte[] iv = EMF.generateAESIVforLBA((int) (baseLBA+lba));

        //System.out.println("lba ="+lba);
        //System.out.println("iv=" + Util.byteArrayToHexString(iv));

		try {
			emf_encrypter.init(true, new ParametersWithIV(emfKeyParam, iv));
			filekey_decrypter.init(false, new ParametersWithIV(fileKeyParam, iv));
	        
        	byte[] block = new byte[blockSize];
        	byte[] block_ciphertext = new byte[blockSize];
			
	        int x = super.read(block, 0, len);
	        emf_encrypter.processBytes(block, 0, blockSize, block_ciphertext, 0);
	        filekey_decrypter.processBytes(block_ciphertext, 0, blockSize, block, 0);
        
	        /*//TODO inspect slack space
	        if (len != 4096)
	        	System.out.println(Util.byteArrayToHexString(block));
	        	
        	*/
	        System.arraycopy(block, offset, b, boffset, len);
	        return len;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		} 
        
    }

}
