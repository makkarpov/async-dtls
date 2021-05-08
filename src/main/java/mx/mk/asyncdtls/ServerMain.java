package mx.mk.asyncdtls;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.util.HashedWheelTimer;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class ServerMain {
    private static class DatagramPacketHandler extends ChannelDuplexHandler {
        private InetSocketAddress endpoint;

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            ctx.write(new DatagramPacket((ByteBuf) msg, endpoint), promise);
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            DatagramPacket packet = (DatagramPacket) msg;
            endpoint = packet.sender();
            ctx.fireChannelRead(packet.content());
        }
    }

    private static class TlsServer extends DefaultTlsServer {
        private final BcTlsCrypto crypto;
        private final X509CertificateHolder certificate;
        private final AsymmetricKeyParameter privateKey;

        public TlsServer(BcTlsCrypto crypto, X509CertificateHolder certificate, AsymmetricKeyParameter privateKey) {
            super(crypto);
            this.crypto = crypto;
            this.certificate = certificate;
            this.privateKey = privateKey;
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
        protected TlsCredentialedSigner getECDSASignerCredentials() throws IOException {
            return new BcDefaultTlsCredentialedSigner(
                    new TlsCryptoParameters(context),
                    crypto,
                    privateKey,
                    new Certificate(new TlsCertificate[]{
                            new BcTlsCertificate(crypto, certificate.getEncoded())
                    }),
                    new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa)
            );
        }
    }

    public static void main(String[] args) throws Exception {
        NioEventLoopGroup group = new NioEventLoopGroup();
        HashedWheelTimer timer = new HashedWheelTimer();

        CertificateUtils.CertificateResult cert = CertificateUtils.generateCertificate();
        BcTlsCrypto crypto = new BcTlsCrypto(SecureRandom.getInstance("SHA1PRNG"));
        TlsServer server = new TlsServer(crypto, cert.certificate, cert.privateKey);

        boolean classic = true;

        if (classic) {
            DatagramSocket socket = new DatagramSocket(33333);
            int limit = 1432;
            DatagramTransport socketTransport = new DatagramTransport() {
                SocketAddress endpoint;

                @Override
                public int getReceiveLimit() throws IOException {
                    return limit;
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
                    return limit;
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
            };

            DTLSServerProtocol protocol = new DTLSServerProtocol();
            DatagramTransport transport = protocol.accept(server, socketTransport);
            while (true) {
                byte[] buf = new byte[limit];
                int r = transport.receive(buf, 0, limit, 0);
                System.out.println(r + ":" + new String(buf, 0, r, StandardCharsets.UTF_8));
            }
        } else {
            Channel ch = new Bootstrap()
                    .group(group)
                    .channel(NioDatagramChannel.class)
                    .handler(new ChannelInitializer<DatagramChannel>() {
                        @Override
                        protected void initChannel(DatagramChannel ch) throws Exception {
                            ch.pipeline()
                                    .addLast(new DatagramPacketHandler())
                                    .addLast(new DTLSServerHandler(server, timer));
                        }
                    })
                    .bind(33333)
                    .sync().channel();

            System.out.println("Channel bound to " + ch.localAddress());
        }
    }
}
