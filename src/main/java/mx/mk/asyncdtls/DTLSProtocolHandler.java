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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Per-session server handler. This handler accepts raw ByteBuf's, not DatagramPackets.
 */
public class DTLSProtocolHandler extends ChannelDuplexHandler {
    @FunctionalInterface
    public interface ProtocolConstructor {
        DTLSAsyncProtocol create(DTLSAsyncTransport transport, TlsTimer timer) throws IOException;
    }

    private Timer timer;
    private ChannelHandlerContext handlerContext;
    private EventLoop eventLoop;

    private final TlsTimer tlsTimer = (target, delayMillis) -> {
        Timeout t = timer.newTimeout(tt -> eventLoop.execute(target), delayMillis, TimeUnit.MILLISECONDS);
        return t::cancel;
    };

    private final ProtocolConstructor constructor;
    private DTLSAsyncProtocol protocol;
    private byte[] receiveBuffer;
    private boolean contextPrinted;

    public DTLSProtocolHandler(Timer timer, ProtocolConstructor constructor) throws IOException {
        this.timer = timer;
        this.constructor = constructor;
    }

    @Override
    public void channelRegistered(ChannelHandlerContext ctx) throws Exception {
        handlerContext = ctx;
        eventLoop = ctx.channel().eventLoop();
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        DTLSAsyncTransport transport = new DTLSAsyncTransport() {
            final List<byte[]> bufferedMessages = new ArrayList<>();
            final int lengthLimit = 1432;

            @Override
            public int getReceiveLimit() throws IOException {
                return lengthLimit;
            }

            @Override
            public void exceptionCaught(Throwable cause) {
                handlerContext.pipeline().fireExceptionCaught(cause);
                close();
            }

            @Override
            public void close() {
                handlerContext.channel().close();
            }

            @Override
            public int getSendLimit() throws IOException {
                return lengthLimit;
            }

            @Override
            public void send(byte[] buf, int off, int len) throws IOException {
                bufferedMessages.add(Arrays.copyOfRange(buf, off, off + len));
            }

            @Override
            public void flush(boolean isRetransmit) {
                int idx = 0;
                while (idx < bufferedMessages.size()) {
                    int length = bufferedMessages.get(idx).length;
                    int toIdx = idx;

                    for (int i = idx + 1; i < bufferedMessages.size(); i++) {
                        int msgLength = bufferedMessages.get(i).length;
                        if (length + msgLength < lengthLimit) {
                            length += msgLength;
                            toIdx = i;
                        } else {
                            break;
                        }
                    }

                    ByteBuf buf = handlerContext.alloc().ioBuffer(length);
                    for (int i = idx; i <= toIdx; i++) {
                        buf.writeBytes(bufferedMessages.get(i));
                    }
                    ctx.write(buf);

                    idx = toIdx + 1;
                }

                bufferedMessages.clear();
                ctx.flush();
            }
        };

        protocol = constructor.create(transport, tlsTimer);

        ctx.fireChannelActive();
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msgObject, ChannelPromise promise) throws Exception {
        ByteBuf msg = (ByteBuf) msgObject;
        byte[] msgBytes = new byte[msg.readableBytes()];
        msg.readBytes(msgBytes);

        protocol.send(msgBytes, 0, msgBytes.length);
        promise.setSuccess();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msgObject) throws Exception {
        ByteBuf msg = (ByteBuf) msgObject;
        byte[] msgBytes = new byte[msg.readableBytes()];
        msg.readBytes(msgBytes);

        protocol.pushReceivedDatagram(msgBytes, 0, msgBytes.length);

        if (protocol.handshakeCompleted() && !contextPrinted) {
            Utils.printContext(protocol.context());
            contextPrinted = true;
        }

        if (receiveBuffer == null || receiveBuffer.length < msgBytes.length) {
            receiveBuffer = new byte[msgBytes.length];
        }

        int r;
        do {
            r = protocol.receive(receiveBuffer, 0, receiveBuffer.length);

            if (r >= 0) {
                ByteBuf data = ctx.alloc().ioBuffer(r);
                data.writeBytes(receiveBuffer, 0, r);
                ctx.fireChannelRead(data);
            }
        } while (r >= 0);
    }
}
