import org.bouncycastle.util.encoders.UTF8;

import java.nio.charset.StandardCharsets;

public abstract class CryptoService {

    public CryptoService() {
    }

    static int[] keymin = new int[]{87, -74, -71, -37, -37, 56, -60, -63, -81, -55, 40, -95, -60, 48, 108, -35, -67, 120, -120, -78, -9, 33, 95, -56, -72, 45, -4, -113, -29, 8, 95, -46};

    public int Get_Dec_from_Hex(String s) {
        int a = IndexOfCh(Cipher.HEX, s.charAt(0));
        int b = IndexOfCh(Cipher.HEX, s.charAt(1));
        int res = a * 16 + b;
        return res;
    }

    public int[] GetByteKey(String key) {
        int[] mas = new int[key.length() / 2];
        for (int i = 0; i < (key.length() / 2); i++) {
            String cs = key.substring(i * 2, 2 + (i * 2));
            int a = Get_Dec_from_Hex(cs);
            mas[i] = a;
        }
        return mas;
    }

    public int IndexOf(int[] mas, int x) {
        for (int index = 0; index < mas.length; index++) {
            if (mas[index] == x) {
                return index;
            }
        }
        return -1;
    }

    public int IndexOfCh(char[] mas, char x) {
        for (int index = 0; index < mas.length; index++) {
            if (mas[index] == x) {
                return index;
            }
        }
        return -1;
    }

    public int[] Xor(int[] ms, int[] mas) {
        String ss = "";
        for (int i = 0; i < mas.length; i++) {
            int q = ms[i];
            ms[i] = (int) (q ^ mas[i]);
        }
        return ms;
    }

    public static String GetKeyNormal(int[] keymin) {
        String res = "";
        String str = "";
        for (int i = 0; i < keymin.length; i++) {
            if (keymin[i] < 0) {
                int a = 128 - Math.abs(keymin[i]);
                int b = 128 + a;
                keymin[i] = b;
            }
            str += Integer.toHexString(keymin[i]);
            if (str.length() < 2) {
                str = "0" + str;
            }

            res += str;
            str = "";
        }
        System.out.println(res);
        return res;
    }
}
