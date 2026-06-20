import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import type { DashboardAuthConfig } from '../config';
import type { DashboardPasskey, DashboardUser } from './users';

export type WebAuthnRegistrationChallenge = {
  challenge: string;  // base64url
  userId: string;
};

export type WebAuthnAuthChallenge = {
  challenge: string;  // base64url
};

export async function beginRegistration(
  auth: DashboardAuthConfig,
  user: DashboardUser
): Promise<{ options: Awaited<ReturnType<typeof generateRegistrationOptions>>; challenge: string }> {
  const options = await generateRegistrationOptions({
    rpName: auth.rpName,
    rpID: auth.rpId,
    userID: Buffer.from(user.id),
    userName: user.shepherdAccount,
    userDisplayName: user.displayName,
    excludeCredentials: user.passkeys.map((pk) => ({
      id: pk.credentialId,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });
  return { options, challenge: options.challenge };
}

export async function finishRegistration(
  auth: DashboardAuthConfig,
  response: RegistrationResponseJSON,
  expectedChallenge: string,
  label: string
): Promise<DashboardPasskey> {
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: auth.origin,
    expectedRPID: auth.rpId,
    requireUserVerification: false,
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('Registration verification failed.');
  }

  const { credential } = verification.registrationInfo;
  return {
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    label: label || 'Passkey',
    createdAt: new Date().toISOString(),
    lastUsedAt: new Date().toISOString(),
  };
}

export async function beginAuthentication(
  auth: DashboardAuthConfig,
  allowedPasskeys?: DashboardPasskey[]
): Promise<{ options: Awaited<ReturnType<typeof generateAuthenticationOptions>>; challenge: string }> {
  const options = await generateAuthenticationOptions({
    rpID: auth.rpId,
    allowCredentials: allowedPasskeys?.map((pk) => ({ id: pk.credentialId })),
    userVerification: 'preferred',
  });
  return { options, challenge: options.challenge };
}

export async function finishAuthentication(
  auth: DashboardAuthConfig,
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  passkey: DashboardPasskey
): Promise<{ verified: boolean; newCounter: number }> {
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: auth.origin,
    expectedRPID: auth.rpId,
    credential: {
      id: passkey.credentialId,
      publicKey: Buffer.from(passkey.publicKey, 'base64url'),
      counter: passkey.counter,
    },
    requireUserVerification: false,
  });

  return {
    verified: verification.verified,
    newCounter: verification.authenticationInfo?.newCounter ?? passkey.counter,
  };
}
