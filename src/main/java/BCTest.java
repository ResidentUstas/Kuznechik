import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;

public class BCTest {
    public void BouncyTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] IV16 = new byte[0];

        GOST3412_2015Engine cipher = new GOST3412_2015Engine();
        GOST3412_2015Engine cipher2 = new GOST3412_2015Engine();
        byte[] hex = Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        KeyParameter key = new KeyParameter(hex);

        cipher.init(false, key);
        cipher2.init(true, key);

        byte[] in = "This is testThis".getBytes();
        System.out.println("In: " + Arrays.toString(in));
        byte[] out = new byte[in.length];
        cipher.processBlock(in, 0, out, 0);

        System.out.println("Out: " + Arrays.toString(out));
        byte[] out2 = new byte[in.length];
        cipher.processBlock(out, 0, out2, 0);

        System.out.println("Out: " + Arrays.toString(out2));

    }

    public void Test2() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Security.addProvider(new BouncyCastleProvider());
        Security.setProperty("crypto.policy", "unlimited");
        byte pIVLen = 8;
        KeyGenerator myGenerator = KeyGenerator.getInstance("GOST3412-2015", "BC");

        /* Initialise the generator */
        myGenerator.init(256);
        SecretKey myKey = myGenerator.generateKey();

        byte[] myIV = new byte[pIVLen];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(myIV);
        String result1 = "";
        for (int i = 0; i < myIV.length; i++) {
            result1 += Integer.toHexString(myIV[i]);
        }

        System.out.println("IV: " + result1);
        System.out.println(Arrays.toString(myKey.getEncoded()));
        System.out.println(Arrays.toString(myIV));

        Cipher myCipherCode = Cipher.getInstance("GOST3412-2015" + "/CTR/NoPadding", "BC");
        Cipher myCipherDecode = Cipher.getInstance("GOST3412-2015" + "/CTR/NoPadding", "BC");
        myCipherCode.init(Cipher.ENCRYPT_MODE, myKey, new IvParameterSpec(myIV));
        myCipherDecode.init(Cipher.DECRYPT_MODE, myKey, new IvParameterSpec(myIV));

        byte[] msg = Strings.toByteArray("сталкер 2 в сердце слава вдв");

        LocalDateTime dt = LocalDateTime.now();
        ////System.out.println(dt);

        byte[] enc = myCipherCode.doFinal(msg);
        System.out.println(Duration.between(LocalDateTime.now(), dt));
        dt = LocalDateTime.now();

        byte[] dec = myCipherDecode.doFinal(enc);
        System.out.println(Duration.between(LocalDateTime.now(), dt));
        dt = LocalDateTime.now();

        System.out.println(Arrays.toString(enc));
        int[] mas = new int[enc.length];
        String result = "";
        for (int i = 0; i < mas.length; i++) {
            mas[i] = enc[i];
            result += Integer.toHexString(mas[i]);
        }

        System.out.println("result: " + result);
        System.out.println(Strings.fromUTF8ByteArray(dec));

    }
}
