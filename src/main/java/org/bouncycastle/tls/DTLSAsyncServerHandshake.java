package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

class DTLSAsyncServerHandshake extends DTLSAsyncHandshake {
    private static final int STATE_WANT_CLIENT_HELLO    = 0;
    private static final int STATE_WANT_SUPPL_DATA      = 1;
    private static final int STATE_WANT_CERTIFICATE     = 2;
    private static final int STATE_WANT_KEY_EXCHANGE    = 3;
    private static final int STATE_WANT_CERT_VERIFY     = 4;
    private static final int STATE_WANT_FINISHED        = 5;
    private static final int STATE_HANDSHAKE_COMPLETE   = 6;

    TlsServer server;
    TlsServerContextImpl serverContext;
    DTLSRecordLayer recordLayer;
    TlsSession tlsSession;
    SessionParameters sessionParameters;
    TlsSecret sessionMasterSecret;
    SecurityParameters securityParameters;
    int[] offeredCipherSuites;
    Hashtable clientExtensions;
    Hashtable serverExtensions;
    boolean offeredExtendedMasterSecret = false;
    boolean resumedSession = false;
    boolean expectSessionTicket = false;
    TlsKeyExchange keyExchange;
    TlsHandshakeHash certificateVerifyHash;
    TlsCredentials serverCredentials;
    CertificateRequest certificateRequest;
    TlsHeartbeat heartbeat;
    short heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;

    int state;

    DTLSAsyncServerHandshake(TlsServer server, TlsTimer timer, DTLSAsyncTransport transport, DTLSRequest request)
        throws IOException
    {
        this.server = server;
        serverContext = new TlsServerContextImpl(server.getCrypto());
        server.init(serverContext);
        serverContext.handshakeBeginning(server);

        securityParameters = serverContext.getSecurityParametersHandshake();
        securityParameters.extendedPadding = server.shouldUseExtendedPadding();

        recordLayer = new DTLSRecordLayer(serverContext, timer, server, transport);
        server.notifyCloseHandle(recordLayer);

        handshake = new DTLSReliableHandshake(serverContext, recordLayer, server.getHandshakeTimeoutMillis(), request);

        state = STATE_WANT_CLIENT_HELLO;

        if (request != null) {
            receiveClientHello(request);
        }
    }

    @Override
    void pushReceivedDatagram(byte[] data, int offset, int length) throws IOException {
        recordLayer.pushReceivedDatagram(data, offset, length);
        handshake.startFlight();

        boolean result;
        do {
            switch (state) {
            case STATE_WANT_CLIENT_HELLO:
                result = receiveClientHello(null);
                break;

            case STATE_WANT_SUPPL_DATA:
                result = receiveSupplementalData();
                break;

            case STATE_WANT_CERTIFICATE:
                result = receiveCertificate();
                break;

            case STATE_WANT_KEY_EXCHANGE:
                result = receiveKeyExchange();
                break;

            case STATE_WANT_CERT_VERIFY:
                result = receiveCertificateVerify();
                break;

            case STATE_WANT_FINISHED:
                result = receiveFinished();
                break;

            default:
                throw new IllegalStateException("Unexpected server handshake state: " + state);
            }

            result &= state != STATE_HANDSHAKE_COMPLETE;
        } while (result);

        handshake.finishFlight();
    }

    @Override
    boolean handshakeCompleted() {
        return state == STATE_HANDSHAKE_COMPLETE;
    }

    @Override
    DTLSRecordLayer recordLayer() {
        return recordLayer;
    }

    @Override
    TlsContext context() {
        return serverContext;
    }

    @Override
    void abort(short alertDescription) {
        invalidateSession();
        clear();
        recordLayer.fail(alertDescription);
    }

    @Override
    void clear() {
        if (securityParameters != null) {
            securityParameters.clear();
        }
    }

    private boolean receiveClientHello(DTLSRequest request) throws IOException {
        DTLSReliableHandshake.Message clientMessage;
        if (null == request)
        {
            clientMessage = receiveMessage();
            if (clientMessage == null) {
                return false;
            }

            // NOTE: DTLSRecordLayer requires any DTLS version, we don't otherwise constrain this
            // ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();

            if (clientMessage.getType() == HandshakeType.client_hello)
            {
                processClientHello(clientMessage.getBody());
                consumeMessage();
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }
        else
        {
            processClientHello(request.getClientHello());
        }

        /*
         * NOTE: Currently no server support for session resumption
         *
         * If adding support, ensure securityParameters.tlsUnique is set to the localVerifyData, but
         * ONLY when extended_master_secret has been negotiated (otherwise NULL).
         */
        {
            // TODO[resumption]

            tlsSession = TlsUtils.importSession(TlsUtils.EMPTY_BYTES, null);
            sessionParameters = null;
            sessionMasterSecret = null;
        }

        securityParameters.sessionID = tlsSession.getSessionID();

        server.notifySession(tlsSession);

        {
            byte[] serverHelloBody = generateServerHello(recordLayer);

            // TODO[dtls13] Ideally, move this into generateServerHello once legacy_record_version clarified
            {
                ProtocolVersion recordLayerVersion = serverContext.getServerVersion();
                recordLayer.setReadVersion(recordLayerVersion);
                recordLayer.setWriteVersion(recordLayerVersion);
            }

            handshake.sendMessage(HandshakeType.server_hello, serverHelloBody);
        }

        handshake.getHandshakeHash().notifyPRFDetermined();

        Vector serverSupplementalData = server.getServerSupplementalData();
        if (serverSupplementalData != null)
        {
            byte[] supplementalDataBody = generateSupplementalData(serverSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        keyExchange = TlsUtils.initKeyExchangeServer(serverContext, server);
        serverCredentials = TlsUtils.establishServerCredentials(server);

        // Server certificate
        {
            Certificate serverCertificate = null;

            ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
            if (serverCredentials == null)
            {
                keyExchange.skipServerCredentials();
            }
            else
            {
                keyExchange.processServerCredentials(serverCredentials);

                serverCertificate = serverCredentials.getCertificate();

                sendCertificateMessage(serverContext, handshake, serverCertificate, endPointHash);
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
            CertificateStatus certificateStatus = server.getCertificateStatus();
            if (certificateStatus != null)
            {
                byte[] certificateStatusBody = generateCertificateStatus(certificateStatus);
                handshake.sendMessage(HandshakeType.certificate_status, certificateStatusBody);
            }
        }

        byte[] serverKeyExchange = keyExchange.generateServerKeyExchange();
        if (serverKeyExchange != null)
        {
            handshake.sendMessage(HandshakeType.server_key_exchange, serverKeyExchange);
        }

        if (serverCredentials != null)
        {
            certificateRequest = server.getCertificateRequest();

            if (null == certificateRequest)
            {
                /*
                 * For static agreement key exchanges, CertificateRequest is required since
                 * the client Certificate message is mandatory but can only be sent if the
                 * server requests it.
                 */
                if (!keyExchange.requiresCertificateVerify())
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }
            }
            else
            {
                if (TlsUtils.isTLSv12(serverContext) == (certificateRequest.getSupportedSignatureAlgorithms() == null))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                certificateRequest = TlsUtils.validateCertificateRequest(certificateRequest, keyExchange);

                TlsUtils.establishServerSigAlgs(securityParameters, certificateRequest);

                TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(), securityParameters.getServerSigAlgs());

                byte[] certificateRequestBody = generateCertificateRequest(certificateRequest);
                handshake.sendMessage(HandshakeType.certificate_request, certificateRequestBody);
            }
        }

        handshake.sendMessage(HandshakeType.server_hello_done, TlsUtils.EMPTY_BYTES);

        boolean forceBuffering = false;
        TlsUtils.sealHandshakeHash(serverContext, handshake.getHandshakeHash(), forceBuffering);

        state = STATE_WANT_SUPPL_DATA;
        return true;
    }

    private boolean receiveSupplementalData() throws IOException {
        DTLSReliableHandshake.Message clientMessage = receiveMessage();
        if (clientMessage == null) {
            return false;
        }

        if (clientMessage.getType() == HandshakeType.supplemental_data) {
            processClientSupplementalData(clientMessage.getBody());
            consumeMessage();
        } else {
            server.processClientSupplementalData(null);
        }

        state = STATE_WANT_CERTIFICATE;
        return true;
    }

    private boolean receiveCertificate() throws IOException {
        DTLSReliableHandshake.Message clientMessage = receiveMessage();
        if (clientMessage == null) {
            return false;
        }

        if (certificateRequest == null)
        {
            keyExchange.skipClientCredentials();
        }
        else
        {
            if (clientMessage.getType() == HandshakeType.certificate)
            {
                processClientCertificate(clientMessage.getBody());
                consumeMessage();
            }
            else
            {
                if (TlsUtils.isTLSv12(serverContext))
                {
                    /*
                     * RFC 5246 If no suitable certificate is available, the client MUST send a
                     * certificate message containing no certificates.
                     *
                     * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                notifyClientCertificate(Certificate.EMPTY_CHAIN);
            }
        }

        state = STATE_WANT_KEY_EXCHANGE;
        return true;
    }

    private boolean receiveKeyExchange() throws IOException {
        DTLSReliableHandshake.Message clientMessage = receiveMessage();
        if (clientMessage == null) {
            return false;
        }

        if (clientMessage.getType() == HandshakeType.client_key_exchange)
        {
            processClientKeyExchange(clientMessage.getBody());
            consumeMessage();
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());

        TlsProtocol.establishMasterSecret(serverContext, keyExchange);
        recordLayer.initPendingEpoch(TlsUtils.initCipher(serverContext));

        /*
         * RFC 5246 7.4.8 This message is only sent following a client certificate that has signing
         * capability (i.e., all certificates except those containing fixed Diffie-Hellman
         * parameters).
         */
        {
            certificateVerifyHash = handshake.prepareToFinish();

            if (expectCertificateVerifyMessage()) {
                state = STATE_WANT_CERT_VERIFY;
            } else {
                state = STATE_WANT_FINISHED;
            }
        }

        return true;
    }

    private boolean receiveCertificateVerify() throws IOException {
        byte[] certificateVerifyBody = receiveMessageBody(HandshakeType.certificate_verify);
        if (certificateVerifyBody == null) {
            return false;
        }

        processCertificateVerify(certificateVerifyBody, certificateVerifyHash);
        consumeMessage();

        state = STATE_WANT_FINISHED;
        return true;
    }

    private boolean receiveFinished() throws IOException {
        if (securityParameters.peerVerifyData == null) {
            // NOTE: Calculated exclusive of the actual Finished message from the client
            securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(serverContext,
                    handshake.getHandshakeHash(), false);
        }

        byte[] finishedBody = receiveMessageBody(HandshakeType.finished);
        if (finishedBody == null) {
            return false;
        }

        processFinished(finishedBody, securityParameters.getPeerVerifyData());

        if (expectSessionTicket)
        {
            NewSessionTicket newSessionTicket = server.getNewSessionTicket();
            byte[] newSessionTicketBody = generateNewSessionTicket(newSessionTicket);
            handshake.sendMessage(HandshakeType.new_session_ticket, newSessionTicketBody);
        }

        // NOTE: Calculated exclusive of the Finished message itself
        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(serverContext,
                handshake.getHandshakeHash(), true);
        handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

        handshake.finish(true);

        sessionMasterSecret = securityParameters.getMasterSecret();

        sessionParameters = new SessionParameters.Builder()
                .setCipherSuite(securityParameters.getCipherSuite())
                .setCompressionAlgorithm(securityParameters.getCompressionAlgorithm())
                .setExtendedMasterSecret(securityParameters.isExtendedMasterSecret())
                .setLocalCertificate(securityParameters.getLocalCertificate())
                .setMasterSecret(serverContext.getCrypto().adoptSecret(sessionMasterSecret))
                .setNegotiatedVersion(securityParameters.getNegotiatedVersion())
                .setPeerCertificate(securityParameters.getPeerCertificate())
                .setPSKIdentity(securityParameters.getPSKIdentity())
                .setSRPIdentity(securityParameters.getSRPIdentity())
                // TODO Consider filtering extensions that aren't relevant to resumed sessions
                .setServerExtensions(serverExtensions)
                .build();

        tlsSession = TlsUtils.importSession(tlsSession.getSessionID(), sessionParameters);

        securityParameters.tlsUnique = securityParameters.getPeerVerifyData();

        serverContext.handshakeComplete(server, tlsSession);

        recordLayer.initHeartbeat(heartbeat, HeartbeatMode.peer_allowed_to_send == heartbeatPolicy);

        state = STATE_HANDSHAKE_COMPLETE;
        return true;
    }

    protected byte[] generateCertificateRequest(CertificateRequest certificateRequest)
            throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateRequest.encode(serverContext, buf);
        return buf.toByteArray();
    }

    protected byte[] generateCertificateStatus(CertificateStatus certificateStatus)
            throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // TODO[tls13] Ensure this cannot happen for (D)TLS1.3+
        certificateStatus.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateNewSessionTicket(NewSessionTicket newSessionTicket)
            throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        newSessionTicket.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateServerHello(DTLSRecordLayer recordLayer)
            throws IOException
    {
        TlsServerContextImpl context = serverContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        ProtocolVersion server_version = server.getServerVersion();
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
                    && server.shouldUseGMTUnixTime();

            securityParameters.serverRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, context);

            if (!server_version.equals(ProtocolVersion.getLatestDTLS(server.getProtocolVersions())))
            {
                TlsUtils.writeDowngradeMarker(server_version, securityParameters.getServerRandom());
            }
        }

        {
            int cipherSuite = validateSelectedCipherSuite(server.getSelectedCipherSuite(),
                    AlertDescription.internal_error);

            if (!TlsUtils.isValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) ||
                    !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
        }

        serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(server.getServerExtensions());

        server.getServerExtensionsForConnection(serverExtensions);

        ProtocolVersion legacy_version = server_version;
        if (server_version.isLaterVersionOf(ProtocolVersion.DTLSv12))
        {
            legacy_version = ProtocolVersion.DTLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverExtensions, server_version);
        }

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        if (securityParameters.isSecureRenegotiation())
        {
            byte[] renegExtData = TlsUtils.getExtensionData(serverExtensions, TlsProtocol.EXT_RenegotiationInfo);
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
                serverExtensions.put(TlsProtocol.EXT_RenegotiationInfo,
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
            securityParameters.extendedMasterSecret = offeredExtendedMasterSecret
                    && server.shouldUseExtendedMasterSecret();

            if (securityParameters.isExtendedMasterSecret())
            {
                TlsExtensionsUtils.addExtendedMasterSecretExtension(serverExtensions);
            }
            else if (server.requiresExtendedMasterSecret())
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            else if (resumedSession && !server.allowLegacyResumption())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        // Heartbeats
        if (null != heartbeat || HeartbeatMode.peer_allowed_to_send == heartbeatPolicy)
        {
            TlsExtensionsUtils.addHeartbeatExtension(serverExtensions, new HeartbeatExtension(heartbeatPolicy));
        }



        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverExtensions);
        securityParameters.applicationProtocolSet = true;

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        if (!serverExtensions.isEmpty())
        {
            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(serverExtensions);

            securityParameters.maxFragmentLength = evaluateMaxFragmentLengthExtension(resumedSession,
                    clientExtensions, serverExtensions, AlertDescription.internal_error);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(serverExtensions);

            /*
             * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
             * a session resumption handshake.
             */
            if (!resumedSession)
            {
                // TODO[tls13] See RFC 8446 4.4.2.1
                if (TlsUtils.hasExpectedEmptyExtensionData(serverExtensions,
                        TlsExtensionsUtils.EXT_status_request_v2, AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 2;
                }
                else if (TlsUtils.hasExpectedEmptyExtensionData(serverExtensions,
                        TlsExtensionsUtils.EXT_status_request, AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 1;
                }
            }

            expectSessionTicket = !resumedSession
                    && TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.internal_error);
        }

        applyMaxFragmentLengthExtension(recordLayer, securityParameters.getMaxFragmentLength());



        ServerHello serverHello = new ServerHello(legacy_version, securityParameters.getServerRandom(),
                tlsSession.getSessionID(), securityParameters.getCipherSuite(), serverExtensions);

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        serverHello.encode(serverContext, buf);
        return buf.toByteArray();
    }

    protected void invalidateSession()
    {
        if (sessionMasterSecret != null)
        {
            sessionMasterSecret.destroy();
            sessionMasterSecret = null;
        }

        if (sessionParameters != null)
        {
            sessionParameters.clear();
            sessionParameters = null;
        }

        if (tlsSession != null)
        {
            tlsSession.invalidate();
            tlsSession = null;
        }
    }

    protected void notifyClientCertificate(Certificate clientCertificate)
            throws IOException
    {
        if (null == certificateRequest)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsUtils.processClientCertificate(serverContext, clientCertificate, keyExchange, server);
    }

    protected void processClientCertificate(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        Certificate.ParseOptions options = new Certificate.ParseOptions()
                .setMaxChainLength(server.getMaxCertificateChainLength());

        Certificate clientCertificate = Certificate.parse(options, serverContext, buf, null);

        TlsProtocol.assertEmpty(buf);

        notifyClientCertificate(clientCertificate);
    }

    protected void processCertificateVerify(byte[] body, TlsHandshakeHash handshakeHash)
            throws IOException
    {
        if (certificateRequest == null)
        {
            throw new IllegalStateException();
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        TlsServerContextImpl context = serverContext;
        DigitallySigned certificateVerify = DigitallySigned.parse(context, buf);

        TlsProtocol.assertEmpty(buf);

        TlsUtils.verifyCertificateVerifyClient(context, certificateRequest, certificateVerify, handshakeHash);
    }

    protected void processClientHello(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        ClientHello clientHello = ClientHello.parse(buf, NullOutputStream.INSTANCE);
        processClientHello(clientHello);
    }

    protected void processClientHello(ClientHello clientHello)
            throws IOException
    {
        // TODO Read RFCs for guidance on the expected record layer version number
        ProtocolVersion legacy_version = clientHello.getVersion();
        offeredCipherSuites = clientHello.getCipherSuites();

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        clientExtensions = clientHello.getExtensions();



        TlsServerContextImpl context = serverContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        if (!legacy_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        context.setRSAPreMasterSecretVersion(legacy_version);

        context.setClientSupportedVersions(
                TlsExtensionsUtils.getSupportedVersionsExtensionClient(clientExtensions));

        ProtocolVersion client_version = legacy_version;
        if (null == context.getClientSupportedVersions())
        {
            if (client_version.isLaterVersionOf(ProtocolVersion.DTLSv12))
            {
                client_version = ProtocolVersion.DTLSv12;
            }

            context.setClientSupportedVersions(client_version.downTo(ProtocolVersion.DTLSv10));
        }
        else
        {
            client_version = ProtocolVersion.getLatestDTLS(context.getClientSupportedVersions());
        }

        if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_DTLS.isEqualOrEarlierVersionOf(client_version))
        {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        context.setClientVersion(client_version);

        server.notifyClientVersion(context.getClientVersion());

        securityParameters.clientRandom = clientHello.getRandom();

        server.notifyFallback(Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));

        server.notifyOfferedCipherSuites(offeredCipherSuites);

        /*
         * TODO[resumption] Check RFC 7627 5.4. for required behaviour
         */

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */

            /*
             * When a ClientHello is received, the server MUST check if it includes the
             * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If it does, set the secure_renegotiation flag
             * to TRUE.
             */
            if (Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            {
                securityParameters.secureRenegotiation = true;
            }

            /*
             * The server MUST check if the "renegotiation_info" extension is included in the
             * ClientHello.
             */
            byte[] renegExtData = TlsUtils.getExtensionData(clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
            if (renegExtData != null)
            {
                /*
                 * If the extension is present, set secure_renegotiation flag to TRUE. The
                 * server MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake.
                 */
                securityParameters.secureRenegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        server.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        offeredExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(clientExtensions);

        if (clientExtensions != null)
        {
            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(clientExtensions);

            securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientExtensions);

            /*
             * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
             * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
             */
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version))
            {
                TlsUtils.establishClientSigAlgs(securityParameters, clientExtensions);
            }

            securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);

            // Heartbeats
            {
                HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(clientExtensions);
                if (null != heartbeatExtension)
                {
                    if (HeartbeatMode.peer_allowed_to_send == heartbeatExtension.getMode())
                    {
                        heartbeat = server.getHeartbeat();
                    }

                    heartbeatPolicy = server.getHeartbeatPolicy();
                }
            }

            server.processClientExtensions(clientExtensions);
        }
    }

    protected void processClientKeyExchange(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        keyExchange.processClientKeyExchange(buf);

        TlsProtocol.assertEmpty(buf);
    }

    protected void processClientSupplementalData(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        Vector clientSupplementalData = TlsProtocol.readSupplementalDataMessage(buf);
        server.processClientSupplementalData(clientSupplementalData);
    }

    protected boolean expectCertificateVerifyMessage()
    {
        if (null == certificateRequest)
        {
            return false;
        }

        Certificate clientCertificate = serverContext.getSecurityParametersHandshake().getPeerCertificate();

        return null != clientCertificate && !clientCertificate.isEmpty()
                && (null == keyExchange || keyExchange.requiresCertificateVerify());
    }
}
