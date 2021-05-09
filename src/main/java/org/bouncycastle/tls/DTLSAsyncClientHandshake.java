package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

class DTLSAsyncClientHandshake extends DTLSAsyncHandshake {
    private static final int STATE_WANT_SERVER_HELLO        = 0;
    private static final int STATE_WANT_RESUMED_FINISHED    = 1;
    private static final int STATE_WANT_SUPPL_DATA          = 2;
    private static final int STATE_WANT_CERTIFICATE         = 3;
    private static final int STATE_WANT_CERT_STATUS         = 4;
    private static final int STATE_WANT_KEY_EXCHANGE        = 5;
    private static final int STATE_WANT_CERT_REQUEST        = 6;
    private static final int STATE_WANT_HELLO_DONE          = 7;
    private static final int STATE_WANT_SESSION_TICKET      = 8;
    private static final int STATE_WANT_FINISHED            = 9;
    private static final int STATE_HANDSHAKE_COMPLETE       = 10;

    TlsClient client;
    TlsClientContextImpl clientContext;
    DTLSRecordLayer recordLayer;
    TlsSession tlsSession;
    SessionParameters sessionParameters;
    SecurityParameters securityParameters;
    TlsSecret sessionMasterSecret;
    int[] offeredCipherSuites;
    Hashtable clientExtensions;
    Hashtable serverExtensions;
    boolean resumedSession = false;
    boolean expectSessionTicket = false;
    Hashtable clientAgreements;
    TlsKeyExchange keyExchange;
    TlsAuthentication authentication;
    CertificateStatus certificateStatus;
    CertificateRequest certificateRequest;
    TlsCredentials clientCredentials;
    TlsHeartbeat heartbeat;
    short heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;

    int state;
    byte[] clientHelloBody;
    
    DTLSAsyncClientHandshake(TlsClient client, TlsTimer timer, DTLSAsyncTransport transport) throws IOException {
        this.client = client;
        clientContext = new TlsClientContextImpl(client.getCrypto());

        client.init(clientContext);
        clientContext.handshakeBeginning(client);

        securityParameters = clientContext.getSecurityParametersHandshake();
        securityParameters.extendedPadding = client.shouldUseExtendedPadding();

        TlsSession sessionToResume = client.getSessionToResume();
        if (sessionToResume != null && sessionToResume.isResumable())
        {
            SessionParameters sessionParameters = sessionToResume.exportSessionParameters();

            /*
             * NOTE: If we ever enable session resumption without extended_master_secret, then
             * renegotiation MUST be disabled (see RFC 7627 5.4).
             */
            if (sessionParameters != null
                    && (sessionParameters.isExtendedMasterSecret()
                    || (!client.requiresExtendedMasterSecret() && client.allowLegacyResumption())))
            {
                TlsSecret masterSecret = sessionParameters.getMasterSecret();
                if (masterSecret.isAlive())
                {
                    tlsSession = sessionToResume;
                    this.sessionParameters = sessionParameters;
                    sessionMasterSecret = clientContext.getCrypto().adoptSecret(masterSecret);
                }
            }
        }

        recordLayer = new DTLSRecordLayer(clientContext, timer, client, transport);
        client.notifyCloseHandle(recordLayer);

        handshake = new DTLSReliableHandshake(clientContext, recordLayer, client.getHandshakeTimeoutMillis(), null);

        clientHelloBody = generateClientHello();
        recordLayer.setWriteVersion(ProtocolVersion.DTLSv10);

        handshake.startFlight();
        handshake.sendMessage(HandshakeType.client_hello, clientHelloBody);
        handshake.finishFlight();

        state = STATE_WANT_SERVER_HELLO;
    }

    @Override
    void pushReceivedDatagram(byte[] data, int offset, int length) throws IOException {
        recordLayer.pushReceivedDatagram(data, offset, length);
        handshake.startFlight();

        boolean result;
        do {
            switch (state) {
            case STATE_WANT_SERVER_HELLO:
                result = receiveServerHello();
                break;

            case STATE_WANT_RESUMED_FINISHED:
                result = receiveResumedFinished();
                break;

            case STATE_WANT_SUPPL_DATA:
                result = receiveSupplementalData();
                break;

            case STATE_WANT_CERTIFICATE:
                result = receiveCertificate();
                break;

            case STATE_WANT_CERT_STATUS:
                result = receiveCertificateStatus();
                break;

            case STATE_WANT_KEY_EXCHANGE:
                result = receiveKeyExchange();
                break;

            case STATE_WANT_CERT_REQUEST:
                result = receiveCertificateRequest();
                break;

            case STATE_WANT_HELLO_DONE:
                result = receiveServerHelloDone();
                break;

            case STATE_WANT_SESSION_TICKET:
                result = receiveSessionTicket();
                break;

            case STATE_WANT_FINISHED:
                result = receiveFinished();
                break;

            default:
                throw new IllegalStateException("Unexpected client handshake state: " + state);
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
        return clientContext;
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

    private boolean receiveServerHello() throws IOException {
        DTLSReliableHandshake.Message serverMessage = receiveMessage();
        if (serverMessage == null) {
            return false;
        }

        // TODO Consider stricter HelloVerifyRequest protocol (limit number of cookie attempts)
        if (serverMessage.getType() == HandshakeType.hello_verify_request) {
            consumeMessage();

            byte[] cookie = processHelloVerifyRequest(serverMessage.getBody());
            byte[] patched = patchClientHelloWithCookie(clientHelloBody, cookie);

            handshake.resetAfterHelloVerifyRequestClient();
            handshake.sendMessage(HandshakeType.client_hello, patched);
            return true;
        }

        if (serverMessage.getType() == HandshakeType.server_hello)
        {
            ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();
            reportServerVersion(recordLayerVersion);
            recordLayer.setWriteVersion(recordLayerVersion);

            processServerHello(serverMessage.getBody());
            consumeMessage();
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        handshake.getHandshakeHash().notifyPRFDetermined();

        applyMaxFragmentLengthExtension(recordLayer, securityParameters.getMaxFragmentLength());

        if (resumedSession)
        {
            securityParameters.masterSecret = sessionMasterSecret;
            recordLayer.initPendingEpoch(TlsUtils.initCipher(clientContext));

            // NOTE: Calculated exclusive of the actual Finished message from the server
            securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(clientContext,
                    handshake.getHandshakeHash(), true);

            state = STATE_WANT_RESUMED_FINISHED;
            return true;
        }

        invalidateSession();

        tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);
        sessionParameters = null;
        sessionMasterSecret = null;

        state = STATE_WANT_SUPPL_DATA;
        return true;
    }

    private boolean receiveResumedFinished() throws IOException {
        byte[] finishedBody = receiveMessageBody(HandshakeType.finished);
        if (finishedBody == null) {
            return false;
        }

        processFinished(finishedBody, securityParameters.getPeerVerifyData());

        // NOTE: Calculated exclusive of the Finished message itself
        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(clientContext,
                handshake.getHandshakeHash(), false);
        handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

        handshake.finish(false);

        if (securityParameters.isExtendedMasterSecret())
        {
            securityParameters.tlsUnique = securityParameters.getPeerVerifyData();
        }

        clientContext.handshakeComplete(client, tlsSession);

        recordLayer.initHeartbeat(heartbeat, HeartbeatMode.peer_allowed_to_send == heartbeatPolicy);
        state = STATE_HANDSHAKE_COMPLETE;
        return true;
    }

    private boolean receiveSupplementalData() throws IOException {
        DTLSReliableHandshake.Message serverMessage = receiveMessage();
        if (serverMessage == null) {
            return false;
        }

        if (serverMessage.getType() == HandshakeType.supplemental_data)
        {
            processServerSupplementalData(serverMessage.getBody());
            consumeMessage();
        }
        else
        {
            client.processServerSupplementalData(null);
        }

        keyExchange = TlsUtils.initKeyExchangeClient(clientContext, client);
        state = STATE_WANT_CERTIFICATE;
        return true;
    }

    private boolean receiveCertificate() throws IOException {
        DTLSReliableHandshake.Message serverMessage = receiveMessage();
        if (serverMessage == null) {
            return false;
        }

        if (serverMessage.getType() == HandshakeType.certificate)
        {
            processServerCertificate(serverMessage.getBody());
            consumeMessage();
        }
        else
        {
            // Okay, Certificate is optional
            authentication = null;
        }

        state = STATE_WANT_CERT_STATUS;
        return true;
    }

    private boolean receiveCertificateStatus() throws IOException {
        DTLSReliableHandshake.Message serverMessage = receiveMessage();
        if (serverMessage == null) {
            return false;
        }

        if (serverMessage.getType() == HandshakeType.certificate_status)
        {
            if (securityParameters.getStatusRequestVersion() < 1)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            processCertificateStatus(serverMessage.getBody());
            consumeMessage();
        }
        else
        {
            // Okay, CertificateStatus is optional
        }

        TlsUtils.processServerCertificate(clientContext, certificateStatus, keyExchange,
                authentication, clientExtensions, serverExtensions);

        state = STATE_WANT_KEY_EXCHANGE;
        return true;
    }

    private boolean receiveKeyExchange() throws IOException {
        DTLSReliableHandshake.Message serverMessage = receiveMessage();
        if (serverMessage == null) {
            return false;
        }

        if (serverMessage.getType() == HandshakeType.server_key_exchange)
        {
            processServerKeyExchange(serverMessage.getBody());
            consumeMessage();
        }
        else
        {
            // Okay, ServerKeyExchange is optional
            keyExchange.skipServerKeyExchange();
        }

        state = STATE_WANT_CERT_REQUEST;
        return true;
    }

    private boolean receiveCertificateRequest() throws IOException {
        DTLSReliableHandshake.Message serverMessage = receiveMessage();
        if (serverMessage == null) {
            return false;
        }

        if (serverMessage.getType() == HandshakeType.certificate_request)
        {
            processCertificateRequest(serverMessage.getBody());

            TlsUtils.establishServerSigAlgs(securityParameters, certificateRequest);

            /*
             * TODO Give the client a chance to immediately select the CertificateVerify hash
             * algorithm here to avoid tracking the other hash algorithms unnecessarily?
             */
            TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(), securityParameters.getServerSigAlgs());
            consumeMessage();
        }
        else
        {
            // Okay, CertificateRequest is optional
        }

        state = STATE_WANT_HELLO_DONE;
        return true;
    }

    private boolean receiveServerHelloDone() throws IOException {
        DTLSReliableHandshake.Message serverMessage = receiveMessage();
        if (serverMessage == null) {
            return false;
        }

        if (serverMessage.getType() == HandshakeType.server_hello_done)
        {
            if (serverMessage.getBody().length != 0)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        consumeMessage();

        Vector clientSupplementalData = client.getClientSupplementalData();
        if (clientSupplementalData != null)
        {
            byte[] supplementalDataBody = generateSupplementalData(clientSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        if (null != certificateRequest)
        {
            clientCredentials = TlsUtils.establishClientCredentials(authentication,
                    certificateRequest);

            /*
             * RFC 5246 If no suitable certificate is available, the client MUST send a certificate
             * message containing no certificates.
             *
             * NOTE: In previous RFCs, this was SHOULD instead of MUST.
             */

            Certificate clientCertificate = null;
            if (null != clientCredentials)
            {
                clientCertificate = clientCredentials.getCertificate();
            }

            sendCertificateMessage(clientContext, handshake, clientCertificate, null);
        }

        TlsCredentialedSigner credentialedSigner = null;
        TlsStreamSigner streamSigner = null;

        if (null != clientCredentials)
        {
            keyExchange.processClientCredentials(clientCredentials);

            if (clientCredentials instanceof TlsCredentialedSigner)
            {
                credentialedSigner = (TlsCredentialedSigner)clientCredentials;
                streamSigner = credentialedSigner.getStreamSigner();
            }
        }
        else
        {
            keyExchange.skipClientCredentials();
        }

        boolean forceBuffering = streamSigner != null;
        TlsUtils.sealHandshakeHash(clientContext, handshake.getHandshakeHash(), forceBuffering);

        byte[] clientKeyExchangeBody = generateClientKeyExchange();
        handshake.sendMessage(HandshakeType.client_key_exchange, clientKeyExchangeBody);

        securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());

        TlsProtocol.establishMasterSecret(clientContext, keyExchange);
        recordLayer.initPendingEpoch(TlsUtils.initCipher(clientContext));

        {
            if (credentialedSigner != null)
            {
                DigitallySigned certificateVerify = TlsUtils.generateCertificateVerifyClient(clientContext,
                        credentialedSigner, streamSigner, handshake.getHandshakeHash());
                byte[] certificateVerifyBody = generateCertificateVerify(certificateVerify);
                handshake.sendMessage(HandshakeType.certificate_verify, certificateVerifyBody);
            }

            handshake.prepareToFinish();
        }

        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(clientContext,
                handshake.getHandshakeHash(), false);
        handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

        state = STATE_WANT_SESSION_TICKET;
        return true;
    }

    private boolean receiveSessionTicket() throws IOException {
        if (expectSessionTicket)
        {
            DTLSReliableHandshake.Message serverMessage = receiveMessage();
            if (serverMessage == null) {
                return false;
            }

            if (serverMessage.getType() == HandshakeType.new_session_ticket)
            {
                processNewSessionTicket(serverMessage.getBody());
                consumeMessage();
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        // NOTE: Calculated exclusive of the actual Finished message from the server
        securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(clientContext,
                handshake.getHandshakeHash(), true);

        state = STATE_WANT_FINISHED;
        return true;
    }

    private boolean receiveFinished() throws IOException {
        byte[] finishedBody = receiveMessageBody(HandshakeType.finished);
        if (finishedBody == null) {
            return false;
        }

        consumeMessage();

        processFinished(finishedBody, securityParameters.getPeerVerifyData());

        handshake.finish(false);

        sessionMasterSecret = securityParameters.getMasterSecret();

        sessionParameters = new SessionParameters.Builder()
                .setCipherSuite(securityParameters.getCipherSuite())
                .setCompressionAlgorithm(securityParameters.getCompressionAlgorithm())
                .setExtendedMasterSecret(securityParameters.isExtendedMasterSecret())
                .setLocalCertificate(securityParameters.getLocalCertificate())
                .setMasterSecret(clientContext.getCrypto().adoptSecret(sessionMasterSecret))
                .setNegotiatedVersion(securityParameters.getNegotiatedVersion())
                .setPeerCertificate(securityParameters.getPeerCertificate())
                .setPSKIdentity(securityParameters.getPSKIdentity())
                .setSRPIdentity(securityParameters.getSRPIdentity())
                // TODO Consider filtering extensions that aren't relevant to resumed sessions
                .setServerExtensions(serverExtensions)
                .build();

        tlsSession = TlsUtils.importSession(tlsSession.getSessionID(), sessionParameters);

        securityParameters.tlsUnique = securityParameters.getLocalVerifyData();

        clientContext.handshakeComplete(client, tlsSession);

        recordLayer.initHeartbeat(heartbeat, HeartbeatMode.peer_allowed_to_send == heartbeatPolicy);

        state = STATE_HANDSHAKE_COMPLETE;
        return true;
    }

    protected byte[] generateCertificateVerify(DigitallySigned certificateVerify)
            throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateVerify.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateClientHello()
            throws IOException
    {
        TlsClientContextImpl context = clientContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        context.setClientSupportedVersions(client.getProtocolVersions());

        ProtocolVersion client_version = ProtocolVersion.getLatestDTLS(context.getClientSupportedVersions());
        if (!ProtocolVersion.isSupportedDTLSVersionClient(client_version))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        context.setClientVersion(client_version);

        byte[] session_id = TlsUtils.getSessionID(tlsSession);

        boolean fallback = client.isFallback();

        offeredCipherSuites = client.getCipherSuites();

        if (session_id.length > 0 && sessionParameters != null)
        {
            if (!Arrays.contains(offeredCipherSuites, sessionParameters.getCipherSuite())
                    || CompressionMethod._null != sessionParameters.getCompressionAlgorithm())
            {
                session_id = TlsUtils.EMPTY_BYTES;
            }
        }

        clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(client.getClientExtensions());

        ProtocolVersion legacy_version = client_version;
        if (client_version.isLaterVersionOf(ProtocolVersion.DTLSv12))
        {
            legacy_version = ProtocolVersion.DTLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions,
                    context.getClientSupportedVersions());
        }

        context.setRSAPreMasterSecretVersion(legacy_version);

        securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientExtensions);

        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version))
        {
            TlsUtils.establishClientSigAlgs(securityParameters, clientExtensions);
        }

        securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);

        clientAgreements = TlsUtils.addEarlyKeySharesToClientHello(clientContext, client, clientExtensions);

        if (TlsUtils.isExtendedMasterSecretOptionalDTLS(context.getClientSupportedVersions())
                && client.shouldUseExtendedMasterSecret())
        {
            TlsExtensionsUtils.addExtendedMasterSecretExtension(clientExtensions);
        }
        else if (!TlsUtils.isTLSv13(client_version)
                && client.requiresExtendedMasterSecret())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        {
            boolean useGMTUnixTime = ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(client_version)
                    && client.shouldUseGMTUnixTime();

            securityParameters.clientRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, clientContext);
        }

        // Cipher Suites (and SCSV)
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */
            boolean noRenegExt = (null == TlsUtils.getExtensionData(clientExtensions, TlsProtocol.EXT_RenegotiationInfo));
            boolean noRenegSCSV = !Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

            if (noRenegExt && noRenegSCSV)
            {
                offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            }
        }

        /* (Fallback SCSV)
         * RFC 7507 4. If a client sends a ClientHello.client_version containing a lower value
         * than the latest (highest-valued) version supported by the client, it SHOULD include
         * the TLS_FALLBACK_SCSV cipher suite value in ClientHello.cipher_suites [..]. (The
         * client SHOULD put TLS_FALLBACK_SCSV after all cipher suites that it actually intends
         * to negotiate.)
         */
        if (fallback && !Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV))
        {
            offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV);
        }

        // Heartbeats
        {
            heartbeat = client.getHeartbeat();
            heartbeatPolicy = client.getHeartbeatPolicy();

            if (null != heartbeat || HeartbeatMode.peer_allowed_to_send == heartbeatPolicy)
            {
                TlsExtensionsUtils.addHeartbeatExtension(clientExtensions, new HeartbeatExtension(heartbeatPolicy));
            }
        }

        ClientHello clientHello = new ClientHello(legacy_version, securityParameters.getClientRandom(), session_id,
                TlsUtils.EMPTY_BYTES, offeredCipherSuites, clientExtensions);

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        clientHello.encode(clientContext, buf);
        return buf.toByteArray();
    }

    protected byte[] generateClientKeyExchange()
            throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        keyExchange.generateClientKeyExchange(buf);
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

    protected void processCertificateRequest(byte[] body) throws IOException
    {
        if (null == authentication)
        {
            /*
             * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server to
             * request client identification.
             */
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        certificateRequest = CertificateRequest.parse(clientContext, buf);

        TlsProtocol.assertEmpty(buf);

        certificateRequest = TlsUtils.validateCertificateRequest(certificateRequest, keyExchange);
    }

    protected void processCertificateStatus(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        // TODO[tls13] Ensure this cannot happen for (D)TLS1.3+
        certificateStatus = CertificateStatus.parse(clientContext, buf);

        TlsProtocol.assertEmpty(buf);
    }

    protected byte[] processHelloVerifyRequest(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ProtocolVersion server_version = TlsUtils.readVersion(buf);

        /*
         * RFC 6347 This specification increases the cookie size limit to 255 bytes for greater
         * future flexibility. The limit remains 32 for previous versions of DTLS.
         */
        int maxCookieLength = ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(server_version) ? 255 : 32;

        byte[] cookie = TlsUtils.readOpaque8(buf, 0, maxCookieLength);

        TlsProtocol.assertEmpty(buf);

        // TODO Seems this behaviour is not yet in line with OpenSSL for DTLS 1.2
//        reportServerVersion(server_version);
        if (!server_version.isEqualOrEarlierVersionOf(clientContext.getClientVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return cookie;
    }

    protected void processNewSessionTicket(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);

        TlsProtocol.assertEmpty(buf);

        client.notifyNewSessionTicket(newSessionTicket);
    }

    protected void processServerCertificate(byte[] body)
            throws IOException
    {
        authentication = TlsUtils.receiveServerCertificate(clientContext, client,
                new ByteArrayInputStream(body));
    }

    protected void processServerHello(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ServerHello serverHello = ServerHello.parse(buf);
        ProtocolVersion server_version = serverHello.getVersion();

        serverExtensions = serverHello.getExtensions();



        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        // TODO[dtls13] Check supported_version extension for negotiated version

        reportServerVersion(server_version);

        securityParameters.serverRandom = serverHello.getRandom();

        if (!clientContext.getClientVersion().equals(server_version))
        {
            TlsUtils.checkDowngradeMarker(server_version, securityParameters.getServerRandom());
        }

        {
            byte[] selectedSessionID = serverHello.getSessionID();
            securityParameters.sessionID = selectedSessionID;
            client.notifySessionID(selectedSessionID);
            resumedSession = selectedSessionID.length > 0 && tlsSession != null
                    && Arrays.areEqual(selectedSessionID, tlsSession.getSessionID());
        }

        /*
         * Find out which CipherSuite the server has chosen and check that it was one of the offered
         * ones, and is a valid selection for the negotiated version.
         */
        {
            int cipherSuite = validateSelectedCipherSuite(serverHello.getCipherSuite(),
                    AlertDescription.illegal_parameter);

            if (!TlsUtils.isValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) ||
                    !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
            client.notifySelectedCipherSuite(cipherSuite);
        }

        /*
         * RFC3546 2.2 The extended server hello message format MAY be sent in place of the server
         * hello message when the client has requested extended functionality via the extended
         * client hello message specified in Section 2.1. ... Note that the extended server hello
         * message is only sent in response to an extended client hello message. This prevents the
         * possibility that the extended server hello message could "break" existing TLS 1.0
         * clients.
         */

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */

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
            final boolean acceptedExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(
                    serverExtensions);

            if (acceptedExtendedMasterSecret)
            {
                if (!resumedSession && !client.shouldUseExtendedMasterSecret())
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
            else
            {
                if (client.requiresExtendedMasterSecret()
                        || (resumedSession && !client.allowLegacyResumption()))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }

            securityParameters.extendedMasterSecret = acceptedExtendedMasterSecret;
        }

        /*
         *
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message. However, see RFC 5746 exception below. We always include
         * the SCSV, so an Extended Server Hello is always allowed.
         */
        if (serverExtensions != null)
        {
            Enumeration e = serverExtensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();

                /*
                 * RFC 5746 3.6. Note that sending a "renegotiation_info" extension in response to a
                 * ClientHello containing only the SCSV is an explicit exception to the prohibition
                 * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                 * only allowed because the client is signaling its willingness to receive the
                 * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                 */
                if (extType.equals(TlsProtocol.EXT_RenegotiationInfo))
                {
                    continue;
                }

                /*
                 * RFC 5246 7.4.1.4 An extension type MUST NOT appear in the ServerHello unless the
                 * same extension type appeared in the corresponding ClientHello. If a client
                 * receives an extension type in ServerHello that it did not request in the
                 * associated ClientHello, it MUST abort the handshake with an unsupported_extension
                 * fatal alert.
                 */
                if (null == TlsUtils.getExtensionData(clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                }

                /*
                 * RFC 3546 2.3. If [...] the older session is resumed, then the server MUST ignore
                 * extensions appearing in the client hello, and send a server hello containing no
                 * extensions[.]
                 */
                if (resumedSession)
                {
                    // TODO[compat-gnutls] GnuTLS test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-openssl] OpenSSL test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-polarssl] PolarSSL test server sends server extensions e.g. ec_point_formats
//                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        /*
         * RFC 5746 3.4. Client Behavior: Initial Handshake
         */
        {
            /*
             * When a ServerHello is received, the client MUST check if it includes the
             * "renegotiation_info" extension:
             */
            byte[] renegExtData = TlsUtils.getExtensionData(serverExtensions, TlsProtocol.EXT_RenegotiationInfo);
            if (renegExtData != null)
            {
                /*
                 * If the extension is present, set the secure_renegotiation flag to TRUE. The
                 * client MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                 * handshake_failure alert).
                 */
                securityParameters.secureRenegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData,
                        TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        // TODO[compat-gnutls] GnuTLS test server fails to send renegotiation_info extension when resuming
        client.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverExtensions);
        securityParameters.applicationProtocolSet = true;

        // Heartbeats
        {
            HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(serverExtensions);
            if (null == heartbeatExtension)
            {
                heartbeat = null;
                heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;
            }
            else if (HeartbeatMode.peer_allowed_to_send != heartbeatExtension.getMode())
            {
                heartbeat = null;
            }
        }

        Hashtable sessionClientExtensions = clientExtensions, sessionServerExtensions = serverExtensions;

        if (resumedSession)
        {
            if (securityParameters.getCipherSuite() != sessionParameters.getCipherSuite()
                    || CompressionMethod._null != sessionParameters.getCompressionAlgorithm()
                    || !server_version.equals(sessionParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            sessionClientExtensions = null;
            sessionServerExtensions = sessionParameters.readServerExtensions();
        }

        if (sessionServerExtensions != null && !sessionServerExtensions.isEmpty())
        {
            {
                /*
                 * RFC 7366 3. If a server receives an encrypt-then-MAC request extension from a client
                 * and then selects a stream or Authenticated Encryption with Associated Data (AEAD)
                 * ciphersuite, it MUST NOT send an encrypt-then-MAC response extension back to the
                 * client.
                 */
                boolean serverSentEncryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(sessionServerExtensions);
                if (serverSentEncryptThenMAC && !TlsUtils.isBlockCipherSuite(securityParameters.getCipherSuite()))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
                securityParameters.encryptThenMAC = serverSentEncryptThenMAC;
            }

            securityParameters.maxFragmentLength = evaluateMaxFragmentLengthExtension(resumedSession,
                    sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(sessionServerExtensions);

            if (!resumedSession)
            {
                // TODO[tls13] See RFC 8446 4.4.2.1
                if (TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request_v2,
                        AlertDescription.illegal_parameter))
                {
                    securityParameters.statusRequestVersion = 2;
                }
                else if (TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request,
                        AlertDescription.illegal_parameter))
                {
                    securityParameters.statusRequestVersion = 1;
                }
            }

            expectSessionTicket = !resumedSession
                    && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.illegal_parameter);
        }

        if (sessionClientExtensions != null)
        {
            client.processServerExtensions(sessionServerExtensions);
        }
    }

    protected void processServerKeyExchange(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        keyExchange.processServerKeyExchange(buf);

        TlsProtocol.assertEmpty(buf);
    }

    protected void processServerSupplementalData(byte[] body)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        Vector serverSupplementalData = TlsProtocol.readSupplementalDataMessage(buf);
        client.processServerSupplementalData(serverSupplementalData);
    }

    protected void reportServerVersion(ProtocolVersion server_version)
            throws IOException
    {
        TlsClientContextImpl context = clientContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        ProtocolVersion currentServerVersion = securityParameters.getNegotiatedVersion();
        if (null != currentServerVersion)
        {
            if (!currentServerVersion.equals(server_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            return;
        }

        if (!ProtocolVersion.contains(context.getClientSupportedVersions(), server_version))
        {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        securityParameters.negotiatedVersion = server_version;

        TlsUtils.negotiatedVersionDTLSClient(clientContext, client);
    }

    protected static byte[] patchClientHelloWithCookie(byte[] clientHelloBody, byte[] cookie)
            throws IOException
    {
        int sessionIDPos = 34;
        int sessionIDLength = TlsUtils.readUint8(clientHelloBody, sessionIDPos);

        int cookieLengthPos = sessionIDPos + 1 + sessionIDLength;
        int cookiePos = cookieLengthPos + 1;

        byte[] patched = new byte[clientHelloBody.length + cookie.length];
        System.arraycopy(clientHelloBody, 0, patched, 0, cookieLengthPos);
        TlsUtils.checkUint8(cookie.length);
        TlsUtils.writeUint8(cookie.length, patched, cookieLengthPos);
        System.arraycopy(cookie, 0, patched, cookiePos, cookie.length);
        System.arraycopy(clientHelloBody, cookiePos, patched, cookiePos + cookie.length, clientHelloBody.length
                - cookiePos);

        return patched;
    }
}
