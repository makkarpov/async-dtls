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
    public DTLSServerHandler(TlsServer server, Timer timer) throws IOException {
    }

    @Override
    public void channelRegistered(ChannelHandlerContext ctx) throws Exception {
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msgObject) throws Exception {
    }
}
