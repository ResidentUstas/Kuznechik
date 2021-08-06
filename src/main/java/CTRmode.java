import org.bouncycastle.util.Strings;

public class CTRmode extends CryptoService {
    private static byte[] IV = new byte[]{92, -25, -49, 113, 102, -81, -47, -81};
    public static String myIV = "1234567890abcef0";
    public static String openBlock = "1234567890abcef00000000000000000";

    public String  GetNextCTR() {
        int[] ctrB = GetByteKey(openBlock);
        ctrB = CTR_INC(ctrB);
        String result = "";
        String str = "";
        for (int i = 0; i < ctrB.length; i++) {
            str += Integer.toHexString(ctrB[i]);
            if (str.length() < 2) {
                str = "0" + str;
            }
            result += str;
            str = "";
        }

        System.out.println(result);
        openBlock = result;
        return result;
    }

    static int[] CTR_INC(int[] ctr) {
        int[] bit = new int[16];
        int internal = 0;
        bit[15] = 0x01;
        for (int i = 15; i >= 0; i--) {
            internal = ctr[i] + bit[i] + (internal >> 8);
            ctr[i] = internal & 0xff;
        }

        return ctr;
    }
}
