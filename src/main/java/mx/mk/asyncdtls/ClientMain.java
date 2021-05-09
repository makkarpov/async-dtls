package mx.mk.asyncdtls;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.util.HashedWheelTimer;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.SecureRandom;

public class ClientMain {
    private static class TlsClient extends DefaultTlsClient {
        private final BcTlsCrypto crypto;
        private final Utils.CertificateResult certificate;

        public TlsClient(BcTlsCrypto crypto, Utils.CertificateResult certificate) {
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
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                    return certificate.toCredentials(crypto, context);
                }
            };
        }
    }

    public static void main(String[] args) throws Exception {
        Utils.CertificateResult cert = Utils.generateCertificate();
        System.out.println("Local certificate fingerprint: " + cert.fingerprint());
        BcTlsCrypto crypto = new BcTlsCrypto(SecureRandom.getInstance("SHA1PRNG"));
        TlsClient client = new TlsClient(crypto, cert);

        boolean classic = args.length != 0 && args[0].equalsIgnoreCase("classic");
        InetSocketAddress target = new InetSocketAddress("localhost", 33333);

        if (classic) {
            System.out.println("Running in classic (blocking) mode");

            DatagramSocket socket = new DatagramSocket(0);
            socket.connect(target);
            DatagramTransport socketTransport = new UDPTransport(socket, Utils.MTU);

            DTLSTransport transport = new DTLSClientProtocol().connect(client, socketTransport);
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
                                    .addLast(new DatagramPacketHandler(target))
                                    .addLast(PacketLossSimulator.INSTANCE)
                                    .addLast(new DTLSProtocolHandler(timer,
                                            (tr, tim) -> new DTLSClientProtocol().async(client, tim, tr)));
                        }
                    })
                    .bind(0)
                    .sync().channel();
        }
    }
}
