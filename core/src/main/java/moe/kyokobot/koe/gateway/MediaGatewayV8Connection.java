package moe.kyokobot.koe.gateway;

import moe.kyokobot.koe.VoiceServerInfo;
import moe.kyokobot.koe.crypto.EncryptionMode;
import moe.kyokobot.koe.internal.MediaConnectionImpl;
import moe.kyokobot.koe.internal.handler.DiscordUDPConnection;
import moe.kyokobot.koe.internal.json.JsonObject;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class MediaGatewayV8Connection extends AbstractMediaGatewayConnection {
    private static final Logger logger = LoggerFactory.getLogger(MediaGatewayV8Connection.class);

    private int ssrc;
    private SocketAddress address;
    private List<String> encryptionModes;
    private ScheduledFuture<?> heartbeatFuture;
    private int seq = -1;

    private long ping;

    public MediaGatewayV8Connection(MediaConnectionImpl connection, VoiceServerInfo voiceServerInfo) {
        super(connection, voiceServerInfo, 8);
    }

    @Override
    protected void identify() {
        logger.debug("Identifying...");
        sendInternalPayload(Op.IDENTIFY, new JsonObject()
                .addAsString("server_id", connection.getGuildId())
                .addAsString("user_id", connection.getClient().getClientId())
                .add("session_id", voiceServerInfo.getSessionId())
                .add("token", voiceServerInfo.getToken()));
    }

    @Override
    protected void resume() {
        logger.debug("Resuming...");
        sendInternalPayload(Op.RESUME, new JsonObject()
                .addAsString("server_id", connection.getGuildId())
                .add("session_id", voiceServerInfo.getSessionId())
                .add("token", voiceServerInfo.getToken())
                .add("seq_ack", seq));
    }

    @Override
    protected void handlePayload(JsonObject object) {
        var op = object.getInt("op");
        this.seq = object.getInt("seq", seq);

        switch (op) {
            case Op.HELLO: {
                var data = object.getObject("d");
                var interval = data.getInt("heartbeat_interval");

                logger.debug("Received HELLO, heartbeat interval: {}", interval);
                setupHeartbeats(interval);
                break;
            }
            case Op.READY: {
                resumable = true;

                var data = object.getObject("d");
                var port = data.getInt("port");
                var ip = data.getString("ip");
                ssrc = data.getInt("ssrc");
                encryptionModes = data.getArray("modes")
                        .stream()
                        .map(o -> (String) o)
                        .collect(Collectors.toList());
                address = new InetSocketAddress(ip, port);

                connection.getDispatcher().gatewayReady((InetSocketAddress) address, ssrc);
                logger.debug("Got READY, ssrc: {}", ssrc);
                selectProtocol("udp");
                break;
            }
            case Op.SESSION_DESCRIPTION: {
                var data = object.getObject("d");
                reconnectAttempts = 0;
                logger.debug("Got session description: {}", data);

                if (connection.getConnectionHandler() == null) {
                    logger.warn("Received session description before protocol selection?");
                    break;
                }

                connection.getDispatcher().sessionDescription(data);
                connection.getConnectionHandler().handleSessionDescription(data);
                break;
            }
            case Op.HEARTBEAT_ACK: {
                this.ping = System.currentTimeMillis() - object.getObject("d").getInt("t");
                break;
            }
            case Op.RESUMED: {
                reconnectAttempts = 0;

                logger.debug("Resumed successfully");
                break;
            }
            case Op.CLIENT_CONNECT: {
                var data = object.getObject("d");
                var user = data.getString("user_id");
                var audioSsrc = data.getInt("audio_ssrc", 0);
                var videoSsrc = data.getInt("video_ssrc", 0);
                var rtxSsrc = data.getInt("rtx_ssrc", 0);
                connection.getDispatcher().userConnected(user, audioSsrc, videoSsrc, rtxSsrc);
                break;
            }
            case Op.CLIENT_DISCONNECT: {
                var data = object.getObject("d");
                var user = data.getString("user_id");
                connection.getDispatcher().userDisconnected(user);
                break;
            }
            default:
                break;
        }
    }

    @Override
    protected void onClose(int code, @Nullable String reason, boolean remote) {
        super.onClose(code, reason, remote);
        if (this.heartbeatFuture != null) {
            heartbeatFuture.cancel(true);
        }
    }

    @Override
    public long getPing() {
        return this.ping;
    }

    @Override
    public void updateSpeaking(int mask) {
        sendInternalPayload(Op.SPEAKING, new JsonObject()
                .add("speaking", mask)
                .add("delay", 0)
                .add("ssrc", ssrc));
    }

    private void setupHeartbeats(int interval) {
        if (eventExecutor != null) {
            heartbeatFuture = eventExecutor.scheduleAtFixedRate(this::heartbeat, interval, interval,
                    TimeUnit.MILLISECONDS);
        }
    }

    private void heartbeat() {
        sendInternalPayload(Op.HEARTBEAT, new JsonObject()
                .add("t", System.currentTimeMillis())
                .add("seq_ack", seq));
    }

    private void selectProtocol(String protocol) {
        var mode = EncryptionMode.select(encryptionModes);
        logger.debug("Selected preferred encryption mode: {}", mode);

        // known values: ["udp", "webrtc"]
        if (protocol.equals("udp")) {
            var conn = new DiscordUDPConnection(connection, address, ssrc);
            conn.connect().thenAccept(ourAddress -> {
                logger.debug("Connected, our external address is: {}", ourAddress);
                connection.getDispatcher().externalIPDiscovered(ourAddress);

                var udpInfo = new JsonObject()
                        .add("address", ourAddress.getAddress().getHostAddress())
                        .add("port", ourAddress.getPort())
                        .add("mode", mode);

                sendInternalPayload(Op.SELECT_PROTOCOL, new JsonObject()
                        .add("protocol", "udp")
                        .add("data", udpInfo)
                        .combine(udpInfo));
            });

            connection.setConnectionHandler(conn);
            logger.debug("Waiting for session description...");
        } else if (protocol.equals("webrtc")) {
            // do ICE and then generate SDP with info like above?
            throw new IllegalArgumentException("WebRTC protocol is not supported yet!");
        }
    }
}
