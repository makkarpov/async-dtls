package mx.mk.asyncdtls;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.EventLoop;
import io.netty.util.Timeout;
import io.netty.util.Timer;
import org.bouncycastle.tls.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Per-session server handler. This handler accepts raw ByteBuf's, not DatagramPackets.
 */
public class DTLSServerHandler extends ChannelDuplexHandler {
    private final TlsServer server;
    private final Timer timer;

    private EventLoop eventLoop;
    private final TlsTimer tlsTimer = new TlsTimer() {
        @Override
        public TimerTask schedule(Runnable runnable, long timeoutMillis) {
            // Async DTLS protocol requires that all operations must be single-threaded or synchronized externally
            // This is not the case when HashedWheelTimer is used. So we re-schedule operation to channel event loop,
            // which also runs all other channel operations.

            Timeout t = timer.newTimeout((tt) -> eventLoop.execute(runnable), timeoutMillis, TimeUnit.MILLISECONDS);
            return t::cancel;
        }
    };

    private AsyncDTLSProtocol protocol;
    private ChannelHandlerContext handlerContext;

    public DTLSServerHandler(TlsServer server, Timer timer) throws IOException {
        this.server = server;
        this.timer = timer;
    }

    @Override
    public void channelRegistered(ChannelHandlerContext ctx) throws Exception {
        eventLoop = ctx.channel().eventLoop();
        handlerContext = ctx;

        AsyncDTLSTransport transport = new AsyncDTLSTransport() {
            private ByteBuf wrapArray(byte[] buffer, int offset, int length) {
                ByteBuf data = handlerContext.alloc().ioBuffer(length);
                data.writeBytes(buffer, offset, length);
                return data;
            }

            @Override
            public void exceptionCaught(Throwable cause) {
                handlerContext.fireExceptionCaught(cause);
                handlerContext.channel().close();
            }

            @Override
            public void applicationDataReceived(byte[] buffer, int offset, int length) {
                handlerContext.fireChannelRead(wrapArray(buffer, offset, length));
            }

            @Override
            public void close() {
                handlerContext.channel().close();
            }

            @Override
            public int getSendLimit() throws IOException {
                return 1432;
            }

            @Override
            public void send(byte[] buf, int off, int len) throws IOException {
                handlerContext.writeAndFlush(wrapArray(buf, off, len));
            }
        };

        protocol = AsyncDTLSProtocol.server(server, tlsTimer, transport);
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        System.out.println("W: " + msg);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msgObject) throws Exception {
        ByteBuf msg = (ByteBuf) msgObject;
        byte[] data = new byte[msg.readableBytes()];
        msg.readBytes(data);

        protocol.pushReceivedData(data, 0, data.length);
    }
}
