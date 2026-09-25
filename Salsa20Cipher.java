import java.nio.charset.StandardCharsets;

/**
 * A from-scratch implementation of the Salsa20 stream cipher, built for a
 * computer security course. Supports 64, 128, and 256-bit keys and encrypts
 * (equivalently decrypts, since Salsa20 XORs a keystream with the input)
 * hex-encoded plaintext given a key and nonce, both hex-encoded.
 *
 * Usage:
 *   javac Salsa20Cipher.java
 *   java Salsa20Cipher <key_size_bits> <key_hex> <nonce_hex> <text_hex>
 *
 * Example:
 *   java Salsa20Cipher 256 <64 hex chars> <16 hex chars> <hex plaintext>
 */
public class Salsa20Cipher {

    private static final int ROUNDS = 12;

    public static void main(String[] args) {
        if (args.length != 4) {
            System.out.println("Usage: java Salsa20Cipher <key_size_bits> <key_hex> <nonce_hex> <text_hex>");
            System.exit(1);
        }

        int keySize = Integer.parseInt(args[0]);
        byte[] key = hexStringToByteArray(args[1]);
        byte[] nonce = hexStringToByteArray(args[2]);
        byte[] text = hexStringToByteArray(args[3]);

        if (key.length * 8 != keySize) {
            System.out.println("Error: key size does not match the specified key length.");
            System.exit(1);
        }
        if (nonce.length != 8) {
            System.out.println("Error: nonce must be 8 bytes.");
            System.exit(1);
        }
        if (keySize != 64 && keySize != 128 && keySize != 256) {
            System.out.println("Error: invalid key size. Supported sizes are 64, 128, and 256 bits.");
            System.exit(1);
        }

        byte[] ciphertext = salsa20Encrypt(key, nonce, text);
        System.out.println(byteArrayToHexString(ciphertext));
    }

    private static byte[] salsa20Encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        int keySize = key.length * 8;
        byte[] expandedKey = (keySize == 64) ? expand64Key(key, nonce) : expandKey(key, nonce);

        byte[] block = expandBlock(expandedKey, 0, nonce);
        byte[] keystream = salsa20Hash(block);

        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            ciphertext[i] = (byte) (keystream[i % 64] ^ plaintext[i]);
        }
        return ciphertext;
    }

    private static byte[] expandKey(byte[] key, byte[] nonce) {
        byte[] constants = "expand 32-byte k".getBytes(StandardCharsets.US_ASCII);
        byte[] expandedKey = new byte[constants.length + key.length + nonce.length];
        System.arraycopy(constants, 0, expandedKey, 0, constants.length);
        System.arraycopy(key, 0, expandedKey, constants.length, key.length);
        System.arraycopy(nonce, 0, expandedKey, constants.length + key.length, nonce.length);
        return expandedKey;
    }

    private static byte[] expand64Key(byte[] key, byte[] nonce) {
        byte[] alpha0 = {0x61, 0x70, 0x78, 0x65};
        byte[] alpha1 = {0x20, 0x20, 0x34, 0x68};
        byte[] alpha2 = {0x31, 0x2d, 0x79, 0x62};
        byte[] alpha3 = {0x6b, 0x20, 0x65, 0x74};

        byte[] expandedKey = new byte[64];
        for (int i = 0; i < 4; i++) {
            int index = i * 16;
            System.arraycopy(alpha0, 0, expandedKey, index, alpha0.length);
            System.arraycopy(key, i * 4, expandedKey, index + 4, 4);
            System.arraycopy(alpha1, 0, expandedKey, index + 16, alpha1.length);
            System.arraycopy(nonce, i * 4, expandedKey, index + 20, 4);
            System.arraycopy(alpha2, 0, expandedKey, index + 32, alpha2.length);
            System.arraycopy(key, (i + 4) * 4, expandedKey, index + 36, 4);
            System.arraycopy(alpha3, 0, expandedKey, index + 48, alpha3.length);
        }
        return expandedKey;
    }

    private static byte[] salsa20Hash(byte[] inputBlock) {
        int[] x = new int[16];
        for (int i = 0; i < 16; i++) {
            x[i] = inputBlock[i * 4] & 0xFF;
            x[i] |= (inputBlock[i * 4 + 1] & 0xFF) << 8;
            x[i] |= (inputBlock[i * 4 + 2] & 0xFF) << 16;
            x[i] |= (inputBlock[i * 4 + 3] & 0xFF) << 24;
        }

        int[] result = x.clone();
        for (int round = 0; round < ROUNDS; round++) {
            doubleRound(result);
        }
        for (int i = 0; i < 16; i++) {
            result[i] = result[i] + x[i];
        }

        return intArrayToByteArray(result);
    }

    private static void doubleRound(int[] x) {
        quarterRound(x, 0, 4, 8, 12);
        quarterRound(x, 1, 5, 9, 13);
        quarterRound(x, 2, 6, 10, 14);
        quarterRound(x, 3, 7, 11, 15);

        quarterRound(x, 0, 5, 10, 15);
        quarterRound(x, 1, 6, 11, 12);
        quarterRound(x, 2, 7, 8, 13);
        quarterRound(x, 3, 4, 9, 14);
    }

    private static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[b] ^= Integer.rotateLeft(x[a] + x[d], 7);
        x[c] ^= Integer.rotateLeft(x[b] + x[a], 9);
        x[d] ^= Integer.rotateLeft(x[c] + x[b], 13);
        x[a] ^= Integer.rotateLeft(x[d] + x[c], 18);
    }

    private static byte[] expandBlock(byte[] expandedKey, int counter, byte[] nonce) {
        byte[] block = new byte[64];
        System.arraycopy(expandedKey, 0, block, 0, expandedKey.length);
        packIntLittleEndian(block, 48, counter);
        System.arraycopy(nonce, 0, block, 56, nonce.length);
        return block;
    }

    private static byte[] intArrayToByteArray(int[] arr) {
        byte[] result = new byte[arr.length * 4];
        for (int i = 0; i < arr.length; i++) {
            packIntLittleEndian(result, i * 4, arr[i]);
        }
        return result;
    }

    private static void packIntLittleEndian(byte[] out, int offset, int val) {
        out[offset] = (byte) (val & 0xFF);
        out[offset + 1] = (byte) ((val >> 8) & 0xFF);
        out[offset + 2] = (byte) ((val >> 16) & 0xFF);
        out[offset + 3] = (byte) ((val >> 24) & 0xFF);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
