import { randomBytes } from 'crypto'
import { Curve, signedKeyPair } from './crypto'
import { generateRegistrationId } from './generics'
import type { AuthenticationCreds } from '../Types'

export const initAuthCreds = (): AuthenticationCreds => {
    const identityKey = Curve.generateKeyPair()
    return {
        noiseKey: Curve.generateKeyPair(),
        pairingEphemeralKeyPair: Curve.generateKeyPair(),
        signedIdentityKey: identityKey,
        signedPreKey: signedKeyPair(identityKey, 1),
        registrationId: generateRegistrationId(),
        advSecretKey: randomBytes(32).toString('base64'),
        processedHistoryMessages: [],
        nextPreKeyId: 1,
        firstUnuploadedPreKeyId: 1,
        accountSyncCounter: 0,
        accountSettings: { unarchiveChats: false },
        registered: false,
        pairingCode: undefined,
        lastPropHash: undefined,
        routingInfo: undefined,
        additionalData: undefined
    }
}

/**
 * Generate Pairing Code and Session ID
 */
export const generatePairingCodeAndSession = (phone: string, customCode?: string) => {
    const pairingCode = customCode ? customCode : randomBytes(5).toString('base32').slice(0, 8)
    const sessionId = `BILAL-MD~${pairingCode}#${randomBytes(18).toString('base64url')}`
    return { pairingCode, sessionId }
}
