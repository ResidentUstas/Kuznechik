import org.apache.commons.lang3.ArrayUtils;

import java.util.LinkedList;
import java.util.List;

public class Cipher extends CryptoService {
    public static int[] ConstMuteRow = new int[]{1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148};
    public static char[] HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    public static int[] mtabl = new int[256];
    public static String opentxt = "";
    public static List<int[]> keys = new LinkedList<>();
    public static String[] keystr = new String[10];
    public static int[] bytes = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    public static String[] bstr = new String[33];
    public static List<int[]> Consts = new LinkedList<int[]>();

    public int NL[] = new int[]{
            252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
            233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
            249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5,
            132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235,
            52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181,
            112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161,
            150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117,
            25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245,
            36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15,
            236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151,
            96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70,
            146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64,
            134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73,
            76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164,
            45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230,
            244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182};

    public static int[] LeftShift(int[] mas) {
        int l = mas[0];
        for (int i = 0; i < mas.length - 1; i++) {
            mas[i] = mas[i + 1];
        }
        mas[15] = l;
        return mas;
    }

    public void GET_CONST_Ci() {
        int res = 0;
        int lk = 0;
        for (int l = 1; l < 33; l++) {
            bytes[0] = (byte) l;
            bstr[l - 1] = "";
            for (int j = 1; j < 17; j++) {
                for (int i = 0; i < 16; i++) {
                    int ind1 = IndexOf(mtabl, bytes[i]);
                    int ind2 = IndexOf(mtabl, ConstMuteRow[i]);
                    if (ind1 != -1) {
                        ind1 += ind2;
                        if (ind1 > 255) {
                            ind1 -= 255;
                        }
                        if (res != 0) {
                            res = mtabl[ind1] ^ res;
                        } else
                            res += mtabl[ind1];
                    }
                }
                bytes = LeftShift(bytes);
                bytes[15] = res;
                res = 0;
            }
            int[] csc = new int[16];
            for (int p = 0; p < 16; p++) {
                csc[p] = bytes[p];
            }
            ArrayUtils.reverse(csc);
            Consts.add(csc);
            lk++;
            for (int k = 0; k < 16; k++) {
                bytes[k] = 0;
            }
        }
    }

    public String Get_Cipher(String psw, String ctr) {
        mtabl[0] = 1;
        opentxt = ctr;
        for (int i = 1; i < 256; i++) {
            mtabl[i] = mtabl[i - 1] * 2;
            if (mtabl[i] > 255) {
                int spp = mtabl[i] ^ 195;
                spp -= 256;
                mtabl[i] = spp;
            }
        }
        GET_CONST_Ci();
        Get_Keys(psw);
        String result = Get_cipher_text();
        return result;
    }

    public void S_preobr(int[] ms) {
        for (int i = 0; i < ms.length; i++) {
            int q = ms[i];
            ms[i] = (int) NL[q];
        }
    }

    public void L_preobr(int[] ms) {
        int res = 0;
        String ss = "";
        ArrayUtils.reverse(ms);
        for (int j = 1; j < 17; j++) {
            for (int i = 0; i < 16; i++) {
                int ind1 = IndexOf(mtabl, ms[i]);
                int ind2 = IndexOf(mtabl, ConstMuteRow[i]);
                if (ind1 != -1) {
                    ind1 += ind2;
                    if (ind1 > 255) {
                        ind1 -= 255;
                    }
                    if (res != 0) {
                        res = mtabl[ind1] ^ res;
                    } else
                        res += mtabl[ind1];
                }
            }
            ms = LeftShift(ms);
            ms[15] = res;
            res = 0;
        }
        ArrayUtils.reverse(ms);
    }

    public static void Xor_K2(int[] ms, int[] mas) {
        String ss = "";
        for (int i = 0; i < ms.length; i++) {
            int q = ms[i];
            ms[i] = (int) (q ^ mas[i]);
        }
    }

    public void swap_mass(int[] m1, int[] m2) {
        for (int i = 0; i < m1.length; i++) {
            m1[i] = m2[i];
        }
    }

    public void Get_Keys(String key) {
        int[] keyb = GetByteKey(key);
        System.out.println("My byte key: ");

        for (int i=0; i< keyb.length; i++){
            System.out.println(keyb[i]);
        }
        keystr[0] = key.substring(0, 32);
        keystr[1] = key.substring(32, 64);
        keys.add(GetByteKey(keystr[0]));
        keys.add(GetByteKey(keystr[1]));
        String ss = "";
        int[] K1 = new int[16];
        int[] K2 = new int[16];
        int[] K3 = new int[16];
        swap_mass(K2, keys.get(1));
        swap_mass(K1, keys.get(0));
        swap_mass(K3, K1);
        for (int j = 0; j < 32; ) {
            for (int l = 0; l < 8; l++, j++) {
                for (int i = 0; i < 16; i++) {
                    K1[i] = (K1[i] ^ Consts.get(j)[i]);
                }
                S_preobr(K1);
                L_preobr(K1);
                Xor_K2(K1, K2);
                swap_mass(K2, K3);
                swap_mass(K3, K1);
            }
            int[] a = new int[16];
            swap_mass(a, K1);
            keys.add(a);
            int[] b = new int[16];
            swap_mass(b, K2);
            keys.add(b);
        }
    }

    public String Get_cipher_text() {
        int[] op = GetByteKey(opentxt);
        String cipherText = "";
        String str = "";
        for (int i = 0; i < 9; i++) {
            Xor_K2(op, keys.get(i));
            S_preobr(op);
            L_preobr(op);
        }
        Xor_K2(op, keys.get(9));

        for (int i = 0; i < op.length; i++) {
            str += Integer.toHexString(op[i]);
            if (str.length() < 2) {
                str = "0" + str;
            }
            cipherText += str;
            str = "";
        }
        return cipherText;
    }
}
