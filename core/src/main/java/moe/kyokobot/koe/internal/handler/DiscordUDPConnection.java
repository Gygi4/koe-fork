package moe.kyokobot.koe.internal.handler;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.socket.DatagramChannel;
import moe.kyokobot.koe.MediaConnection;
import moe.kyokobot.koe.codec.Codec;
import moe.kyokobot.koe.crypto.EncryptionMode;
import moe.kyokobot.koe.internal.json.JsonArray;
import moe.kyokobot.koe.internal.util.RTPHeaderWriter;
import moe.kyokobot.koe.handler.ConnectionHandler;
import moe.kyokobot.koe.internal.NettyBootstrapFactory;
import moe.kyokobot.koe.internal.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ThreadLocalRandom;

public class DiscordUDPConnection implements Closeable, ConnectionHandler<InetSocketAddress> {
    private static boolean WARNED = false;
    private static final Logger logger = LoggerFactory.getLogger(DiscordUDPConnection.class);

    private final MediaConnection connection;
    private final ByteBufAllocator allocator;
    private final SocketAddress serverAddress;
    private final Bootstrap bootstrap;
    private final int ssrc;

    private EncryptionMode encryptionMode;
    private DatagramChannel channel;
    private byte[] secretKey;

    private char seq;

    public long getSocketFileDescriptor() {
        if (channel instanceof EpollDatagramChannel) {
            EpollDatagramChannel ch = (EpollDatagramChannel) channel;
            return ch.fd().intValue();
        }

        if (!WARNED) {
            WARNED = true;

            boolean supportsEpoll = Epoll.isAvailable();

            if (supportsEpoll) {
                logger.warn("Could not get the UDP Socket file descriptor, audio receive system won't work. Enable Epoll, or disable NAS to be able to send and receive audio simultaneously.");
            } else {
                logger.warn("Could not get the UDP Socket file descriptor, audio receive system won't work. Disable NAS to be able to send and receive audio simultaneously.");
            }
        }

        // SOCKET_INVALID (https://github.com/davidffa/jda-nas-fork/blob/master/udp-queue-natives/udpqueue/udpqueue.c#L26)
        return -1;
    }

    public DiscordUDPConnection(MediaConnection voiceConnection,
                                SocketAddress serverAddress,
                                int ssrc) {
        this.connection = voiceConnection;
        this.allocator = voiceConnection.getOptions().getByteBufAllocator();
        this.serverAddress = Objects.requireNonNull(serverAddress);
        this.bootstrap = NettyBootstrapFactory.datagram(voiceConnection.getOptions());
        this.ssrc = ssrc;
        // should be a random value https://tools.ietf.org/html/rfc1889#section-5.1
        this.seq = (char) (ThreadLocalRandom.current().nextInt() & 0xffff);
    }

    @Override
    public CompletionStage<InetSocketAddress> connect() {
        logger.debug("Connecting to {}...", serverAddress);

        CompletableFuture<InetSocketAddress> future = new CompletableFuture<>();
        bootstrap.handler(new Initializer(this, future))
                .connect(serverAddress)
                .addListener(res -> {
                    if (!res.isSuccess()) {
                        future.completeExceptionally(res.cause());
                    }
                });
        return future;
    }

    @Override
    public void close() {
        if (channel != null && channel.isOpen()) {
            channel.close();
        }
    }

    @Override
    public void handleSessionDescription(JsonObject object) {
        String mode = object.getString("mode");
        String audioCodecName = object.getString("audio_codec");

        encryptionMode = EncryptionMode.get(mode);
        Codec audioCodec = Codec.getAudio(audioCodecName);

        if (audioCodecName != null && audioCodec == null) {
            logger.warn("Unsupported audio codec type: {}, no audio data will be polled", audioCodecName);
        }

        if (encryptionMode == null) {
            throw new IllegalStateException("Encryption mode selected by Discord is not supported by Koe or the " +
                    "protocol changed! Open an issue at https://github.com/KyokoBot/koe");
        }

        JsonArray keyArray = object.getArray("secret_key");
        this.secretKey = new byte[keyArray.size()];

        for (int i = 0; i < secretKey.length; i++) {
            this.secretKey[i] = (byte) (keyArray.getInt(i) & 0xff);
        }

        connection.startAudioFramePolling();
        connection.startVideoFramePolling();
    }

    @Override
    public void sendFrame(byte payloadType, int timestamp, ByteBuf data, int len, boolean extension) {
        ByteBuf buf = createPacket(payloadType, timestamp, data, len, extension);
        if (buf != null) {
            channel.writeAndFlush(buf);
        }
    }

    public ByteBuf createPacket(byte payloadType, int timestamp, ByteBuf data, int len, boolean extension) {
        if (secretKey == null) {
            return null;
        }

        ByteBuf buf = allocator.buffer();
        buf.clear();
        RTPHeaderWriter.writeV2(buf, payloadType, nextSeq(), timestamp, ssrc, extension);
        if (encryptionMode.box(data, len, buf, secretKey)) {
            return buf;
        } else {
            logger.debug("Encryption failed!");
            buf.release();
            // handle failed encryption?
        }

        return null;
    }

    public char nextSeq() {
        if ((seq + 1) > 0xffff) {
            seq = 0;
        } else {
            seq++;
        }

        return seq;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public int getSsrc() {
        return ssrc;
    }

    public EncryptionMode getEncryptionMode() {
        return encryptionMode;
    }

    public SocketAddress getServerAddress() {
        return serverAddress;
    }

    public DatagramChannel getChannel() {
        return channel;
    }

    private static class Initializer extends ChannelInitializer<DatagramChannel> {
        private final DiscordUDPConnection udpConnection;
        private final CompletableFuture<InetSocketAddress> future;

        private Initializer(DiscordUDPConnection udpConnection, CompletableFuture<InetSocketAddress> future) {
            this.udpConnection = udpConnection;
            this.future = future;
        }

        @Override
        protected void initChannel(DatagramChannel datagramChannel) {
            udpConnection.channel = datagramChannel;

            HolepunchHandler handler = new HolepunchHandler(future, udpConnection.ssrc);
            datagramChannel.pipeline().addFirst("handler", handler);

            if (udpConnection.connection.getReceiveHandler() != null) {
                logger.debug("Registering AudioReceiver listener");
                datagramChannel.pipeline().addLast(new AudioReceiverHandler(udpConnection, udpConnection.connection));
            }
        }
    }
}