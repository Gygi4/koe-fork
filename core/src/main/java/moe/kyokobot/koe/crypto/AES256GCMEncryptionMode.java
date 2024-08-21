package moe.kyokobot.koe.crypto;

import io.netty.buffer.ByteBuf;
import com.google.crypto.tink.aead.internal.InsecureNonceAesGcmJce;

public class AES256GCMEncryptionMode implements EncryptionMode {
    private static final int NONCE_BYTES_LENGTH = 12;

    private final byte[] extendedNonce = new byte[NONCE_BYTES_LENGTH];
    private final byte[] associatedData = new byte[NONCE_BYTES_LENGTH];

    private InsecureNonceAesGcmJce cipher;
    private int seq = 0x80000000;

    @Override
    @SuppressWarnings("Duplicates")
    public boolean encrypt(ByteBuf packet, int len, ByteBuf output, byte[] secretKey) {
        var m = new byte[len];
        byte[] c;

        packet.readBytes(m);

        var s = this.seq++;

        extendedNonce[0] = (byte) (s & 0xff);
        extendedNonce[1] = (byte) ((s >> 8) & 0xff);
        extendedNonce[2] = (byte) ((s >> 16) & 0xff);
        extendedNonce[3] = (byte) ((s >> 24) & 0xff);

        // RTP Header already written to the output buffer
        output.readBytes(associatedData);
        output.resetReaderIndex();

        try {
            if (cipher == null)
                cipher = new InsecureNonceAesGcmJce(secretKey);

            c = cipher.encrypt(extendedNonce, m, associatedData);
        } catch (Exception e) {
            return false;
        }

        output.writeBytes(c);
        output.writeIntLE(s);

        return true;
    }

    @Override
    public String getName() {
        return "aead_aes256_gcm_rtpsize";
    }
}
