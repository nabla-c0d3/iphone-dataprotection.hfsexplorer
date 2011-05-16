package org.catacombae.hfsexplorer.iphone;

import java.io.File;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.catacombae.hfsexplorer.Util;
import org.catacombae.hfsexplorer.fs.BaseHFSFileSystemView;
import org.catacombae.hfsexplorer.fs.ImplHFSPlusFileSystemView;
import org.catacombae.jparted.lib.fs.FileSystemHandler;
import org.catacombae.jparted.lib.fs.hfscommon.HFSCommonFileSystemHandler;

import com.dd.plist.NSArray;
import com.dd.plist.NSDictionary;
import com.dd.plist.NSNumber;
import com.dd.plist.PropertyListParser;

public class EMF {
	private static EMF instance = null;
	private int baseLBA;
	
	private boolean isInitialized;
	private byte[][] classKeys = {
			null,
			null,
			null,
			null,
	};
	private byte[] emfKey;
	
	private EMF() {
		isInitialized = false;
		baseLBA = 0;
	}
	public static EMF getInstance() {
		if (instance == null)
			instance = new EMF();
		return instance;
	}
	
	public boolean initialize(FileSystemHandler fsHandler, String fileName) {
		isInitialized = false;
		if (!(fsHandler instanceof HFSCommonFileSystemHandler))
			return false;
		
		BaseHFSFileSystemView fsView = ((HFSCommonFileSystemHandler) fsHandler).getFSView();
		if (!(fsView instanceof ImplHFSPlusFileSystemView))
			return false;
		ImplHFSPlusFileSystemView hfsplusview = (ImplHFSPlusFileSystemView) fsView;
		String volumeID = hfsplusview.getHFSPlusVolumeHeader().getVolumeUniqueID();
		String path;
		System.out.println(fileName);
		path = new File(fileName).getParent();
		System.out.println(path);
		if (path == null)
			path = "./";
		String plistname = path + File.separator + volumeID + ".plist";
		System.out.println("EMF init : " + volumeID);
		
		try {
			NSDictionary rootDict = (NSDictionary)PropertyListParser.parse(new File(plistname));
			if(rootDict.objectForKey("EMF") != null && rootDict.objectForKey("DKey") != null)
			{
				String emf = rootDict.objectForKey("EMF").toString();
				String dkey = rootDict.objectForKey("DKey").toString();
				
				if (rootDict.objectForKey("dataVolumeOffset") instanceof NSNumber)
					baseLBA = ((NSNumber)rootDict.objectForKey("dataVolumeOffset")).intValue();
				System.out.println(emf);
				emfKey = EMF.hexStringToByteArray(emf);
				classKeys[3] = EMF.hexStringToByteArray(dkey);
				
				if (rootDict.objectForKey("classKeys") instanceof NSDictionary)
				{
					NSDictionary ck = (NSDictionary) rootDict.objectForKey("classKeys");
					for(int i=0; i < 3; i++)
					{
						String k = ck.objectForKey(""+(i+1)).toString();
						if (k.length() == 64)
							classKeys[i] = EMF.hexStringToByteArray(k);
					}
				}
				else
					System.out.println("No class keys found in plist, only NSProtectionNone files will be decrypted correctly");
				
				isInitialized = true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return isInitialized;
	}
	
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

	public static byte[] generateAESIVforLBA(int lba)
	{
		byte[] iv = new byte[16];

		for(int i = 0; i < 4; i++)
		{
			if((lba & 1) != 0)
				lba = 0x80000061 ^ (lba >>> 1);
			else
				lba = lba >>> 1;
            System.arraycopy(Util.toByteArrayLE(lba), 0, iv, 4*i, 4);
		}
		return iv;
	}

	public byte[] getEMFKey()
	{
		return emfKey;
	}
	public byte[] unwrapCprotectKey(byte[] cprotect)
	{
		if (cprotect.length != 56 || !isInitialized)
			return null;
		int protection_class = Util.readIntLE(cprotect, 8);
		int wrapped_size = Util.readIntLE(cprotect, 12);
		//System.out.println(protection_class);
		if ( wrapped_size == 40 && (protection_class -1) < classKeys.length) {
			byte[] class_key = classKeys[protection_class-1];
			if (class_key == null)
			{
				System.out.println("Missing class key for class " + protection_class);
				return null;
			}
			System.out.println("Protection class : " + protection_class );
			Wrapper wrapper = new AESWrapEngine();
			wrapper.init(false, new KeyParameter(class_key));
			byte[] in = new byte[40];
			System.arraycopy(cprotect, 16, in, 0, 40);
			try {
				byte[] fileKey = wrapper.unwrap(in, 0, in.length);
				System.out.println("file key = " + Util.byteArrayToHexString(fileKey));
				return fileKey;
			} catch (InvalidCipherTextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}
	public int getBaseLBA() {
		return baseLBA;
	}
}
