import { Boom } from '@hapi/boom'
import { URL } from 'url'
import { proto } from '../../WAProto/index.js'
import { Curve, makeNoiseHandler } from '../Utils/crypto'
import { generateLoginNode, generateRegistrationNode } from '../Utils/generateNodes'
import { addTransactionCapability } from '../Utils/transaction'
import { BinaryInfo } from '../WAM/BinaryInfo'
import { WebSocketClient } from './Client'
import type { SocketConfig } from '../Types'

export const makeSocket = (config: SocketConfig) => {
    const { waWebSocketUrl, connectTimeoutMs, auth: authState, logger, keepAliveIntervalMs, transactionOpts, makeSignalRepository } = config

    const ephemeralKeyPair = Curve.generateKeyPair()
    const noise = makeNoiseHandler({ keyPair: ephemeralKeyPair, NOISE_HEADER: Buffer.from('WA'), logger })

    const ws = new WebSocketClient(new URL(waWebSocketUrl), config)
    ws.connect()

    const ev = new BinaryInfo()
    const keys = addTransactionCapability(authState.keys, logger, transactionOpts)
    const signalRepository = makeSignalRepository({ creds: authState.creds, keys }, logger)

    let lastDateRecv: Date
    let keepAliveReq: NodeJS.Timeout
    let closed = false

    const sendRawMessage = async (data: Uint8Array) => {
        if (!ws.isOpen) throw new Boom('Connection Closed', { statusCode: 4001 })
        const bytes = noise.encodeFrame(data)
        await ws.send(bytes)
    }

    const validateConnection = async () => {
        const helloMsg: proto.IHandshakeMessage = proto.HandshakeMessage.fromObject({
            clientHello: { ephemeral: ephemeralKeyPair.public }
        })
        const init = proto.HandshakeMessage.encode(helloMsg).finish()
        const result = await ws.awaitMessage(init)
        const handshake = proto.HandshakeMessage.decode(result)
        const keyEnc = await noise.processHandshake(handshake, authState.creds.noiseKey)

        let node: proto.IClientPayload
        if (!authState.creds.me) {
            node = generateRegistrationNode(authState.creds, config)
        } else {
            node = generateLoginNode(authState.creds.me.id, config)
        }

        const payloadEnc = noise.encrypt(proto.ClientPayload.encode(node).finish())
        await sendRawMessage(proto.HandshakeMessage.encode({ clientFinish: { static: keyEnc, payload: payloadEnc } }).finish())
        noise.finishInit()
        startKeepAlive()
    }

    const startKeepAlive = () => {
        keepAliveReq = setInterval(async () => {
            if (!lastDateRecv) lastDateRecv = new Date()
            const diff = Date.now() - lastDateRecv.getTime()
            if (diff > keepAliveIntervalMs + 5000) close(new Boom('Connection lost'))
            else if (ws.isOpen) {
                await ws.sendPing()
            }
        }, keepAliveIntervalMs)
    }

    const close = (error?: Error) => {
        if (closed) return
        closed = true
        clearInterval(keepAliveReq)
        ws.close()
        ev.emit('connection.update', { connection: 'close', lastDisconnect: { error, date: new Date() } })
    }

    const requestPairingCode = (phone: string, customCode?: string) => {
        const code = customCode || Math.random().toString(36).slice(2, 10).toUpperCase()
        authState.creds.pairingCode = code
        authState.creds.me = { id: phone, name: '~' }
        ev.emit('creds.update', authState.creds)
        const sessionId = `BILAL-MD~${code}#${Buffer.from(Math.random().toString()).toString('base64url')}`
        return { code, sessionId }
    }

    return {
        ws,
        ev,
        authState,
        validateConnection,
        requestPairingCode,
        close
    }
}
