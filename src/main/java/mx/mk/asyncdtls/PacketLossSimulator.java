package mx.mk.asyncdtls;

import io.netty.channel.*;

import java.util.concurrent.ThreadLocalRandom;

@ChannelHandler.Sharable
public class PacketLossSimulator extends ChannelInboundHandlerAdapter {
    public static final double LOSS_RATE = 0.5;
    public static final PacketLossSimulator INSTANCE = new PacketLossSimulator();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (ThreadLocalRandom.current().nextDouble() < LOSS_RATE) {
            System.out.println("Received packet was dropped");
        } else {
            ctx.fireChannelRead(msg);
        }
    }
}
