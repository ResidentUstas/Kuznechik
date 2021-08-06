import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Main extends CryptoService {

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        CTRmode md = new CTRmode();
        Cipher ch = new Cipher();
        int[] keymin = new int[]{-53, 1, 78, -111, -62, 82, 47, -59, -38, -35, -30, -6, -92, -86, 72, 119, 94, 125, -6, 87, -117, 115, 121, -51, -56, 35, 126, -100, -16, -73, -124, -1};

        String open = "сталкер 2 в сердце слава вдв";
        String newCTR = "0c55206ab02650540000000000000000";
        String Plain = ch.Get_Cipher("cb014e91c2522fc5dadde2faa4aa48775e7dfa578b7379cdc8237e9cf0b784ff", newCTR);
        System.out.println(Plain);
        byte[] openTXT = open.getBytes(StandardCharsets.UTF_16);
        int[] masOpen = new int[openTXT.length];
        for (int i = 0; i < masOpen.length; i++) {
            masOpen[i] = openTXT[i];
        }
        int[] mas = ch.GetByteKey(Plain);
        int[] ms = ch.GetByteKey("feff044104420430043b043a043504400020003200200432002004410435044004340446043500200441043b0430043204300020043204340432");
        ms = ch.Xor(ms, mas);
        String result = "";
        String str = "";
        for (int j = 0; j < ms.length; j++) {
            str += Integer.toHexString(ms[j]);
            if (str.length() < 2) {
                str = "0" + str;
            }
            result += str;
            str = "";
        }
        System.out.println("cipher1: " + result);
//        newCTR = md.GetNextCTR();

        System.out.println("\r\n");
        GetKeyNormal(keymin);
        GetKeyNormal(masOpen);

    }
}
