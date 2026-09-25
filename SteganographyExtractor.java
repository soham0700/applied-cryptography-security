import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Extracts data hidden in the least-significant bit (LSB) of each byte of a
 * carrier file, using a simple custom encoding scheme covered in a computer
 * security course:
 *
 *   [100-byte header] [8 bytes carrying an 0xA5 indicator pattern]
 *   [27 bits carrying the hidden payload's length] [payload bits, 1 per byte]
 *
 * Usage:
 *   javac SteganographyExtractor.java
 *   java SteganographyExtractor <carrier_file> <output_file>
 */
public class SteganographyExtractor {

    private static final int HEADER_BYTES_TO_SKIP = 100;
    private static final int INDICATOR_VALUE = 0xA5;
    private static final int DATA_SIZE_BITS = 27;

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: java SteganographyExtractor <carrier_file> <output_file>");
            return;
        }

        String carrierFile = args[0];
        String outputFile = args[1];

        try (FileInputStream in = new FileInputStream(carrierFile);
             FileOutputStream out = new FileOutputStream(outputFile)) {

            in.skip(HEADER_BYTES_TO_SKIP);
            verifyIndicatorPattern(in, carrierFile);

            int dataSize = readDataSize(in, carrierFile);
            System.out.println("Data size = " + dataSize + " bytes");

            int bytesWritten = extractData(in, out, dataSize, carrierFile);
            System.out.println("Data extraction completed. Bytes written = " + bytesWritten);

        } catch (IOException e) {
            System.err.println("Extraction failed: " + e.getMessage());
        }
    }

    /** Confirms the carrier actually contains our steganographic marker, one bit per byte. */
    private static void verifyIndicatorPattern(FileInputStream in, String fileName) throws IOException {
        for (int i = 0; i < 8; ++i) {
            int reconstructed = 0;
            for (int bit = 0; bit < 8; ++bit) {
                int b = readByteOrThrow(in, fileName);
                reconstructed ^= ((b & 0x1) << bit);
            }
            if (reconstructed != INDICATOR_VALUE) {
                throw new IOException("file does not contain steganographic data that this tool can read");
            }
        }
    }

    /** Reads the 27-bit payload length, one bit per input byte. */
    private static int readDataSize(FileInputStream in, String fileName) throws IOException {
        int dataSize = 0;
        for (int bit = 0; bit < DATA_SIZE_BITS; ++bit) {
            int b = readByteOrThrow(in, fileName);
            dataSize ^= ((b & 0x1) << bit);
        }
        return dataSize;
    }

    /** Reads dataSize bytes of hidden payload, one bit per input byte, and writes them out. */
    private static int extractData(FileInputStream in, FileOutputStream out, int dataSize, String fileName) throws IOException {
        int bytesWritten = 0;
        int currentByte = 0;
        int bitsFilled = 0;

        for (int i = 0; i < dataSize * 8; ++i) {
            int b = readByteOrThrow(in, fileName);
            currentByte ^= ((b & 0x1) << bitsFilled);
            ++bitsFilled;
            if (bitsFilled == 8) {
                out.write(currentByte);
                ++bytesWritten;
                currentByte = 0;
                bitsFilled = 0;
            }
        }
        return bytesWritten;
    }

    private static int readByteOrThrow(FileInputStream in, String fileName) throws IOException {
        int b = in.read();
        if (b == -1) {
            throw new IOException("unexpected end of file in " + fileName);
        }
        return b;
    }
}
