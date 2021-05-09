package mx.mk.asyncdtls;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.socket.DatagramPacket;

import java.net.InetSocketAddress;

public class DatagramPacketHandler extends ChannelDuplexHandler {
    private InetSocketAddress endpoint;

    public DatagramPacketHandler() {
        this(null);
    }

    public DatagramPacketHandler(InetSocketAddress endpoint) {
        this.endpoint = endpoint;
    }

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
