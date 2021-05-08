package org.bouncycastle.tls;

public interface TlsTimer {
    interface TimerTask {
        void cancel();
    }

    TimerTask schedule(Runnable runnable, long timeoutMillis);
}
