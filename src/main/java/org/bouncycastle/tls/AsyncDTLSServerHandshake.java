package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Vector;

/**
 * This class is *not* thread-safe.
 * @see AsyncDTLSProtocol
 */
class AsyncDTLSServerHandshake extends AsyncDTLSHandshake {
    private static final DTLSServerProtocol serverProtocol = new DTLSServerProtocol();
    private static final int STATE_WAIT_CLIENT_HELLO        = 0;
    private static final int STATE_CLIENT_HELLO_RECEIVED    = 1;
    private static final int STATE_SUPPL_DATA_RECEIVED      = 2;
    private static final int STATE_WAIT_KEY_EXCHANGE        = 3;
    private static final int STATE_WAIT_CERTIFICATE_VERIFY  = 4;
    private static final int STATE_WAIT_FINISHED            = 5;
    private static final int STATE_HANDSHAKE_COMPLETED      = 128;

    private TlsTimer timer;
    private AsyncDTLSRecordLayer recordLayer;
    private DTLSServerProtocol.ServerHandshakeState state;
    private AsyncDTLSReliableHandshake handshake;
    private SecurityParameters securityParameters;
    private int handshakeState;

    private DTLSRequest request;
    private AsyncDTLSReliableHandshake.Message lastMessage;

    private TlsHandshakeHash certificateVerifyHash;

    public AsyncDTLSServerHandshake(TlsServer server, TlsTimer timer, AsyncDTLSTransport transport,
                                    DTLSRequest request) throws IOException {
        this.timer = timer;
        this.state = new DTLSServerProtocol.ServerHandshakeState();
        this.request = request;

        state.server = server;
        state.serverContext = new TlsServerContextImpl(server.getCrypto());
        state.server.init(state.serverContext);
        state.serverContext.handshakeBeginning(state.server);;

        this.recordLayer = new AsyncDTLSRecordLayer(state.serverContext, timer, server, transport);

        securityParameters = state.serverContext.getSecurityParametersHandshake();
        securityParameters.extendedPadding = server.shouldUseExtendedPadding();

        state.server.notifyCloseHandle(recordLayer);

        handshake = new AsyncDTLSReliableHandshake(state.serverContext, recordLayer, request,
                state.server.getHandshakeTimeoutMillis());

        handshakeState = request != null ? STATE_CLIENT_HELLO_RECEIVED : STATE_WAIT_CLIENT_HELLO;
    }

    public AsyncDTLSRecordLayer getRecordLayer() {
        return recordLayer;
    }

    public boolean handshakeCompleted() {
        return handshakeState == STATE_HANDSHAKE_COMPLETED;
    }

    public void pushReceivedData(byte[] data, int off, int len) {
        try {
            recordLayer.pushReceivedData(data, off, len);
            advanceStateMachine();
        } catch (IOException e) {
            handshake.stop();
            recordLayer.getTransport().exceptionCaught(e);
        }
    }

    private void advanceStateMachine() throws IOException {
        while (true) {
            boolean result = false;
            switch (handshakeState) {
            case STATE_WAIT_CLIENT_HELLO:
                result = processClientHello();
                break;

            case STATE_CLIENT_HELLO_RECEIVED:
                result = processSupplementalData();
                break;

            case STATE_SUPPL_DATA_RECEIVED:
                result = processClientCertificate();
                break;

            case STATE_WAIT_KEY_EXCHANGE:
                result = processKeyExchange();
                break;

            case STATE_WAIT_CERTIFICATE_VERIFY:
                result = processCertificateVerify();
                break;

            case STATE_WAIT_FINISHED:
                result = processFinished();
                break;
            }

            if (!result || handshakeState == STATE_HANDSHAKE_COMPLETED) {
                return;
            }
        }
    }

    private AsyncDTLSReliableHandshake.Message receiveMessage() throws IOException {
        if (lastMessage == null) {
            lastMessage = handshake.receiveMessage();
        }

        return lastMessage;
    }

    private byte[] receiveMessageBody(short msgType) throws  IOException {
        AsyncDTLSReliableHandshake.Message message = receiveMessage();
        if (message == null) {
            return null;
        }

        if (message.getType() != msgType)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        return message.getBody();
    }

    private void consumeMessage() {
        lastMessage = null;
    }

    private boolean processClientHello() throws IOException {
        AsyncDTLSReliableHandshake.Message clientMessage;

        if (null == request) {
            clientMessage = receiveMessage();
            if (clientMessage == null) {
                return false;
            }

            if (clientMessage.getType() == HandshakeType.client_hello)
            {
                serverProtocol.processClientHello(state, clientMessage.getBody());
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            consumeMessage();
        } else {
            serverProtocol.processClientHello(state, request.getClientHello());
        }

        /*
         * NOTE: Currently no server support for session resumption
         *
         * If adding support, ensure securityParameters.tlsUnique is set to the localVerifyData, but
         * ONLY when extended_master_secret has been negotiated (otherwise NULL).
         */
        {
            // TODO[resumption]

            state.tlsSession = TlsUtils.importSession(TlsUtils.EMPTY_BYTES, null);
            state.sessionParameters = null;
            state.sessionMasterSecret = null;
        }

        securityParameters.sessionID = state.tlsSession.getSessionID();

        state.server.notifySession(state.tlsSession);

        {
            byte[] serverHelloBody = generateServerHello(state, recordLayer);

            // TODO[dtls13] Ideally, move this into generateServerHello once legacy_record_version clarified
            {
                ProtocolVersion recordLayerVersion = state.serverContext.getServerVersion();
                recordLayer.setReadVersion(recordLayerVersion);
                recordLayer.setWriteVersion(recordLayerVersion);
            }

            handshake.sendMessage(HandshakeType.server_hello, serverHelloBody);
        }

        handshake.getHandshakeHash().notifyPRFDetermined();

        Vector serverSupplementalData = state.server.getServerSupplementalData();
        if (serverSupplementalData != null)
        {
            byte[] supplementalDataBody = DTLSServerProtocol.generateSupplementalData(serverSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        state.keyExchange = TlsUtils.initKeyExchangeServer(state.serverContext, state.server);
        state.serverCredentials = TlsUtils.establishServerCredentials(state.server);

        // Server certificate
        {
            Certificate serverCertificate = null;

            ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
            if (state.serverCredentials == null)
            {
                state.keyExchange.skipServerCredentials();
            }
            else
            {
                state.keyExchange.processServerCredentials(state.serverCredentials);

                serverCertificate = state.serverCredentials.getCertificate();

                sendCertificateMessage(state.serverContext, handshake, serverCertificate, endPointHash);
            }
            securityParameters.tlsServerEndPoint = endPointHash.toByteArray();

            // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
            if (serverCertificate == null || serverCertificate.isEmpty())
            {
                securityParameters.statusRequestVersion = 0;
            }
        }

        if (securityParameters.getStatusRequestVersion() > 0)
        {
            CertificateStatus certificateStatus = state.server.getCertificateStatus();
            if (certificateStatus != null)
            {
                byte[] certificateStatusBody = serverProtocol.generateCertificateStatus(state, certificateStatus);
                handshake.sendMessage(HandshakeType.certificate_status, certificateStatusBody);
            }
        }

        byte[] serverKeyExchange = state.keyExchange.generateServerKeyExchange();
        if (serverKeyExchange != null)
        {
            handshake.sendMessage(HandshakeType.server_key_exchange, serverKeyExchange);
        }

        if (state.serverCredentials != null)
        {
            state.certificateRequest = state.server.getCertificateRequest();

            if (null == state.certificateRequest)
            {
                /*
                 * For static agreement key exchanges, CertificateRequest is required since
                 * the client Certificate message is mandatory but can only be sent if the
                 * server requests it.
                 */
                if (!state.keyExchange.requiresCertificateVerify())
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }
            }
            else
            {
                if (TlsUtils.isTLSv12(state.serverContext) == (state.certificateRequest.getSupportedSignatureAlgorithms() == null))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                state.certificateRequest = TlsUtils.validateCertificateRequest(state.certificateRequest, state.keyExchange);

                TlsUtils.establishServerSigAlgs(securityParameters, state.certificateRequest);

                TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(), securityParameters.getServerSigAlgs());

                byte[] certificateRequestBody = serverProtocol.generateCertificateRequest(state, state.certificateRequest);
                handshake.sendMessage(HandshakeType.certificate_request, certificateRequestBody);
            }
        }

        handshake.sendMessage(HandshakeType.server_hello_done, TlsUtils.EMPTY_BYTES);

        boolean forceBuffering = false;
        TlsUtils.sealHandshakeHash(state.serverContext, handshake.getHandshakeHash(), forceBuffering);

        handshakeState = STATE_CLIENT_HELLO_RECEIVED;
        return true;
    }

    private boolean processSupplementalData() throws IOException {
        AsyncDTLSReliableHandshake.Message message = receiveMessage();
        if (message == null) {
            return false;
        }

        if (message.getType() == HandshakeType.supplemental_data) {
            serverProtocol.processClientSupplementalData(state, message.getBody());
            consumeMessage();
        } else {
            state.server.processClientSupplementalData(null);
        }

        handshakeState = STATE_SUPPL_DATA_RECEIVED;
        return true;
    }

    private boolean processClientCertificate() throws IOException {
        AsyncDTLSReliableHandshake.Message clientMessage = receiveMessage();
        if (clientMessage == null) {
            return false;
        }

        if (state.certificateRequest == null)
        {
            state.keyExchange.skipClientCredentials();
        }
        else
        {
            if (clientMessage.getType() == HandshakeType.certificate)
            {
                serverProtocol.processClientCertificate(state, clientMessage.getBody());
                consumeMessage();
            }
            else
            {
                if (TlsUtils.isTLSv12(state.serverContext))
                {
                    /*
                     * RFC 5246 If no suitable certificate is available, the client MUST send a
                     * certificate message containing no certificates.
                     *
                     * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                serverProtocol.notifyClientCertificate(state, Certificate.EMPTY_CHAIN);
            }
        }

        handshakeState = STATE_WAIT_KEY_EXCHANGE;
        return true;
    }

    private boolean processKeyExchange() throws IOException {
        AsyncDTLSReliableHandshake.Message clientMessage = receiveMessage();
        if (clientMessage == null) {
            return false;
        }

        if (clientMessage.getType() == HandshakeType.client_key_exchange)
        {
            serverProtocol.processClientKeyExchange(state, clientMessage.getBody());
            consumeMessage();
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());

        TlsProtocol.establishMasterSecret(state.serverContext, state.keyExchange);
        recordLayer.initPendingEpoch(TlsUtils.initCipher(state.serverContext));

        /*
         * RFC 5246 7.4.8 This message is only sent following a client certificate that has signing
         * capability (i.e., all certificates except those containing fixed Diffie-Hellman
         * parameters).
         */
        {
            certificateVerifyHash = handshake.prepareToFinish();

            if (serverProtocol.expectCertificateVerifyMessage(state)) {
                handshakeState = STATE_WAIT_CERTIFICATE_VERIFY;
            } else {
                handshakeState = STATE_WAIT_FINISHED;
            }
        }

        return true;
    }

    private boolean processCertificateVerify() throws IOException {
        byte[] certificateVerifyBody = receiveMessageBody(HandshakeType.certificate_verify);
        if (certificateVerifyBody == null) {
            return false;
        }

        serverProtocol.processCertificateVerify(state, certificateVerifyBody, certificateVerifyHash);
        consumeMessage();

        certificateVerifyHash = null;
        handshakeState = STATE_WAIT_FINISHED;
        return true;
    }

    private boolean processFinished() throws IOException {
        byte[] finishedBody = receiveMessageBody(HandshakeType.finished);
        if (finishedBody == null) {
            return false;
        }

        // NOTE: Calculated exclusive of the actual Finished message from the client
        securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(state.serverContext,
                handshake.getHandshakeHash(), false);

        serverProtocol.processFinished(finishedBody, securityParameters.getPeerVerifyData());
        consumeMessage();

        if (state.expectSessionTicket)
        {
            NewSessionTicket newSessionTicket = state.server.getNewSessionTicket();
            byte[] newSessionTicketBody = serverProtocol.generateNewSessionTicket(state, newSessionTicket);
            handshake.sendMessage(HandshakeType.new_session_ticket, newSessionTicketBody);
        }

        // NOTE: Calculated exclusive of the Finished message itself
        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(state.serverContext,
                handshake.getHandshakeHash(), true);
        handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

        handshake.finish();

        state.sessionMasterSecret = securityParameters.getMasterSecret();

        state.sessionParameters = new SessionParameters.Builder()
                .setCipherSuite(securityParameters.getCipherSuite())
                .setCompressionAlgorithm(securityParameters.getCompressionAlgorithm())
                .setExtendedMasterSecret(securityParameters.isExtendedMasterSecret())
                .setLocalCertificate(securityParameters.getLocalCertificate())
                .setMasterSecret(state.serverContext.getCrypto().adoptSecret(state.sessionMasterSecret))
                .setNegotiatedVersion(securityParameters.getNegotiatedVersion())
                .setPeerCertificate(securityParameters.getPeerCertificate())
                .setPSKIdentity(securityParameters.getPSKIdentity())
                .setSRPIdentity(securityParameters.getSRPIdentity())
                // TODO Consider filtering extensions that aren't relevant to resumed sessions
                .setServerExtensions(state.serverExtensions)
                .build();

        state.tlsSession = TlsUtils.importSession(state.tlsSession.getSessionID(), state.sessionParameters);

        securityParameters.tlsUnique = securityParameters.getPeerVerifyData();

        state.serverContext.handshakeComplete(state.server, state.tlsSession);

        recordLayer.initHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);
        handshakeState = STATE_HANDSHAKE_COMPLETED;
        return true;
    }

    protected byte[] generateServerHello(DTLSServerProtocol.ServerHandshakeState state, AsyncDTLSRecordLayer recordLayer)
            throws IOException
    {
        TlsServerContextImpl context = state.serverContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        ProtocolVersion server_version = state.server.getServerVersion();
        {
            if (!ProtocolVersion.contains(context.getClientSupportedVersions(), server_version))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // TODO[dtls13] Read draft/RFC for guidance on the legacy_record_version field
//            ProtocolVersion legacy_record_version = server_version.isLaterVersionOf(ProtocolVersion.DTLSv12)
//                ? ProtocolVersion.DTLSv12
//                : server_version;
//
//            recordLayer.setWriteVersion(legacy_record_version);
            securityParameters.negotiatedVersion = server_version;

            TlsUtils.negotiatedVersionDTLSServer(context);
        }

        {
            boolean useGMTUnixTime = ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(server_version)
                    && state.server.shouldUseGMTUnixTime();

            securityParameters.serverRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, context);

            if (!server_version.equals(ProtocolVersion.getLatestDTLS(state.server.getProtocolVersions())))
            {
                TlsUtils.writeDowngradeMarker(server_version, securityParameters.getServerRandom());
            }
        }

        {
            int cipherSuite = DTLSServerProtocol.validateSelectedCipherSuite(state.server.getSelectedCipherSuite(),
                    AlertDescription.internal_error);

            if (!TlsUtils.isValidCipherSuiteSelection(state.offeredCipherSuites, cipherSuite) ||
                    !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
        }

        state.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(state.server.getServerExtensions());

        state.server.getServerExtensionsForConnection(state.serverExtensions);

        ProtocolVersion legacy_version = server_version;
        if (server_version.isLaterVersionOf(ProtocolVersion.DTLSv12))
        {
            legacy_version = ProtocolVersion.DTLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionServer(state.serverExtensions, server_version);
        }

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        if (securityParameters.isSecureRenegotiation())
        {
            byte[] renegExtData = TlsUtils.getExtensionData(state.serverExtensions, TlsProtocol.EXT_RenegotiationInfo);
            boolean noRenegExt = (null == renegExtData);

            if (noRenegExt)
            {
                /*
                 * Note that sending a "renegotiation_info" extension in response to a ClientHello
                 * containing only the SCSV is an explicit exception to the prohibition in RFC 5246,
                 * Section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                 * because the client is signaling its willingness to receive the extension via the
                 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                 */

                /*
                 * If the secure_renegotiation flag is set to TRUE, the server MUST include an empty
                 * "renegotiation_info" extension in the ServerHello message.
                 */
                state.serverExtensions.put(TlsProtocol.EXT_RenegotiationInfo,
                        TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
            }
        }

        /*
         * RFC 7627 4. Clients and servers SHOULD NOT accept handshakes that do not use the extended
         * master secret [..]. (and see 5.2, 5.3)
         *
         * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server
         * Finished, implementations which support both TLS 1.3 and earlier versions SHOULD indicate
         * the use of the Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
         */
        if (TlsUtils.isTLSv13(server_version))
        {
            securityParameters.extendedMasterSecret = true;
        }
        else
        {
            securityParameters.extendedMasterSecret = state.offeredExtendedMasterSecret
                    && state.server.shouldUseExtendedMasterSecret();

            if (securityParameters.isExtendedMasterSecret())
            {
                TlsExtensionsUtils.addExtendedMasterSecretExtension(state.serverExtensions);
            }
            else if (state.server.requiresExtendedMasterSecret())
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            else if (state.resumedSession && !state.server.allowLegacyResumption())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        // Heartbeats
        if (null != state.heartbeat || HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy)
        {
            TlsExtensionsUtils.addHeartbeatExtension(state.serverExtensions, new HeartbeatExtension(state.heartbeatPolicy));
        }

        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(state.serverExtensions);
        securityParameters.applicationProtocolSet = true;

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        if (!state.serverExtensions.isEmpty())
        {
            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(state.serverExtensions);

            securityParameters.maxFragmentLength = DTLSServerProtocol.evaluateMaxFragmentLengthExtension(
                    state.resumedSession, state.clientExtensions, state.serverExtensions,
                    AlertDescription.internal_error);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(state.serverExtensions);

            /*
             * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
             * a session resumption handshake.
             */
            if (!state.resumedSession)
            {
                // TODO[tls13] See RFC 8446 4.4.2.1
                if (TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions,
                        TlsExtensionsUtils.EXT_status_request_v2, AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 2;
                }
                else if (TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions,
                        TlsExtensionsUtils.EXT_status_request, AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 1;
                }
            }

            state.expectSessionTicket = !state.resumedSession
                    && TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.internal_error);
        }

        applyMaxFragmentLengthExtension(recordLayer, securityParameters.getMaxFragmentLength());

        ServerHello serverHello = new ServerHello(legacy_version, securityParameters.getServerRandom(),
                state.tlsSession.getSessionID(), securityParameters.getCipherSuite(), state.serverExtensions);

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        serverHello.encode(state.serverContext, buf);
        return buf.toByteArray();
    }
}
