package moe.kyokobot.koe.crypto;

import com.google.crypto.tink.aead.internal.InsecureNonceXChaCha20Poly1305;
import com.google.crypto.tink.aead.internal.Poly1305;
import io.netty.buffer.ByteBuf;
import moe.kyokobot.koe.codec.OpusCodec;

import java.nio.ByteBuffer;

public class XChaCha20Poly1305EncryptionMode implements EncryptionMode {
    private static final int NONCE_BYTES_LENGTH = 24;

    private final byte[] extendedNonce = new byte[NONCE_BYTES_LENGTH];
    private final ByteBuffer c = ByteBuffer.allocate(OpusCodec.MAX_FRAME_SIZE + Poly1305.MAC_TAG_SIZE_IN_BYTES + NONCE_BYTES_LENGTH);
    private final byte[] associatedData = new byte[12];

    private InsecureNonceXChaCha20Poly1305 cipher;
    private int seq = 0x80000000;

    @Override
    @SuppressWarnings("Duplicates")
    public boolean encrypt(ByteBuf packet, int len, ByteBuf output, byte[] secretKey) {
        var m = new byte[len];

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
                cipher = new InsecureNonceXChaCha20Poly1305(secretKey);

            c.clear();
            c.limit(len + Poly1305.MAC_TAG_SIZE_IN_BYTES);

            cipher.encrypt(c, extendedNonce, m, associatedData);
        } catch (Exception e) {
            return false;
        }

        output.writeBytes(c.flip());
        output.writeIntLE(s);

        return true;
    }

    @Override
    public String getName() {
        return "aead_xchacha20_poly1305_rtpsize";
    }
}
