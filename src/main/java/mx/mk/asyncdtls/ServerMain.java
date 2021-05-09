package mx.mk.asyncdtls;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.util.HashedWheelTimer;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.Vector;

public class ServerMain {
    private static class MessageEchoHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msgData) throws Exception {
            ByteBuf msg = (ByteBuf) msgData;

            byte[] data = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), data);
            System.out.println("recv: " + Utils.printMessage(data, data.length));

            ctx.write(msg);
        }
    }

    private static class DatagramServerTransport implements DatagramTransport {
        private final DatagramSocket socket;
        private final int mtu;
        private SocketAddress endpoint;

        public DatagramServerTransport(DatagramSocket socket, int mtu) {
            this.socket = socket;
            this.mtu = mtu;
        }

        @Override
        public int getReceiveLimit() throws IOException {
            return mtu;
        }

        @Override
        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
            socket.setSoTimeout(waitMillis);
            java.net.DatagramPacket packet = new java.net.DatagramPacket(buf, off, len);
            socket.receive(packet);
            endpoint = packet.getSocketAddress();
            return packet.getLength();
        }

        @Override
        public int getSendLimit() throws IOException {
            return mtu;
        }

        @Override
        public void send(byte[] buf, int off, int len) throws IOException {
            java.net.DatagramPacket packet = new java.net.DatagramPacket(buf, off, len, endpoint);
            socket.send(packet);
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    private static class TlsServer extends AbstractTlsServer {
        private final BcTlsCrypto crypto;
        private final Utils.CertificateResult certificate;

        public TlsServer(BcTlsCrypto crypto, Utils.CertificateResult certificate) {
            super(crypto);
            this.crypto = crypto;
            this.certificate = certificate;
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return new int[] {
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            };
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
        }

        @Override
        public TlsCredentials getCredentials() throws IOException {
            return certificate.toCredentials(crypto, context);
        }

        @Override
        public CertificateRequest getCertificateRequest() throws IOException {
            Vector supportedSignatures = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
            Vector certificateAuthorities = new Vector();

            return new CertificateRequest(
                    new short[] {
                            ClientCertificateType.rsa_sign,
                            ClientCertificateType.ecdsa_sign
                    },
                    supportedSignatures, certificateAuthorities
            );
        }

        @Override
        public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
        }
    }

    public static void main(String[] args) throws Exception {
        Utils.CertificateResult cert = Utils.generateCertificate();
        System.out.println("Local certificate fingerprint: " + cert.fingerprint());
        BcTlsCrypto crypto = new BcTlsCrypto(SecureRandom.getInstance("SHA1PRNG"));
        TlsServer server = new TlsServer(crypto, cert);

        boolean classic = args.length != 0 && args[0].equalsIgnoreCase("classic");

        if (classic) {
            System.out.println("Running in classic (blocking) mode");

            DatagramSocket socket = new DatagramSocket(33333);
            DatagramTransport socketTransport = new DatagramServerTransport(socket, Utils.MTU);

            DTLSTransport transport = new DTLSServerProtocol().accept(server, socketTransport);
            Utils.printContext(transport.getContext());

            while (true) {
                byte[] buf = new byte[Utils.MTU];
                int r = transport.receive(buf, 0, buf.length, 0);
                System.out.println("recv: " + Utils.printMessage(buf, r));
                transport.send(buf, 0, r);
            }
        } else {
            System.out.println("Running in async mode");

            NioEventLoopGroup group = new NioEventLoopGroup();
            HashedWheelTimer timer = new HashedWheelTimer();
            Channel ch = new Bootstrap()
                    .group(group)
                    .channel(NioDatagramChannel.class)
                    .handler(new ChannelInitializer<DatagramChannel>() {
                        @Override
                        protected void initChannel(DatagramChannel ch) throws Exception {
                            ch.pipeline()
                                .addLast(new DatagramPacketHandler())
                                .addLast(PacketLossSimulator.INSTANCE)
                                .addLast(new DTLSProtocolHandler(timer,
                                        (tr, tim) -> new DTLSServerProtocol().async(server, tim, tr)))
                                .addLast(new MessageEchoHandler());
                        }
                    })
                    .bind(33333)
                    .sync().channel();

            System.out.println("Channel bound to " + ch.localAddress());
        }
    }
}
