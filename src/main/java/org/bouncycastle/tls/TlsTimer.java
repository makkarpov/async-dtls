package org.bouncycastle.tls;

/**
 * Timer used for scheduling deferred operations in asynchronous APIs. Currently used in DTLS for retransmits and
 * timeouts.
 *
 * Note that DTLS API has certain assumptions about threading: timer events must be synchronized with normal methods.
 */
public interface TlsTimer {
    interface TaskHandle {
        /**
         * Cancel scheduled timer task
         */
        void cancel();
    }

    /**
     * Schedule new timer task.
     *
     * @param target        Runnable to be executed
     * @param delayMillis   Delay until execution of runnable
     * @return              Task handle
     */
    TaskHandle schedule(Runnable target, int delayMillis);
}
