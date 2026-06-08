/**
 * Reissue helpers — retiring the OLD agent identity when `provision --reissue`
 * mints a new one.
 *
 * The headline correctness constraint: the old-device IdP revoke needs the OLD
 * agent's signing key, and for a BROKER-NATIVE agent that key lives only in the
 * broker's protected store — which the reissue is about to OVERWRITE (the
 * provisioning broker runs with `--reprovision`). So the revoke MUST happen
 * BEFORE provisioning, routed through the OLD broker booted agent-mode. A LEGACY
 * agent (slot seed in the login keychain) still mints the DPoP in node.
 */
import { deriveAgentKeypair, resolveAgentDeviceId } from './agent-provisioning.js';
import { revokeAgentDevice } from './mls-groups-api.js';
import { startBrokerSupervisor } from './broker-supervisor.js';
import { brokerAvailable } from './broker-ipc.js';

/**
 * Revoke the OLD agent's device at the IdP during a reissue. The IdP evicts its
 * leaf from every group AND purges its KeyPackages, so no peer can re-add the
 * now-dead device via a stale KeyPackage (NoMatchingKeyPackage on the welcome).
 *
 * Two custody postures, same DELETE /v1/identity/devices/:id:
 *  - LEGACY (existing.slotSeed is a 32-byte Buffer): derive the old key in node,
 *    mint the DPoP locally.
 *  - BROKER-NATIVE (existing.slotSeed null): the old key never enters node, so
 *    start the OLD broker agent-mode (it reads the old seed from the protected
 *    store) and route the DELETE through it — the broker mints the old-key DPoP.
 *    Caller MUST invoke this BEFORE the provisioning broker (`--reprovision`)
 *    overwrites the seed, and after stopping the old listener (so the old broker
 *    can bind the scope socket).
 *
 * @param {object} a
 * @param {object} a.existing  - the old bundle from loadAgentVc (deviceId,
 *   slotSeed|null, agentDid, vcCompact, idpUrl)
 * @param {string} a.scope
 * @param {string} a.idpUrl    - fallback IdP if the old bundle didn't record one
 * @param {(l:string)=>void} [a.log]
 * @param {object} [a.deps]    - injectable for tests (_deriveAgentKeypair,
 *   _revokeAgentDevice, _startBrokerSupervisor, _resolveAgentDeviceId)
 * @returns {Promise<string>} the revoked device_id
 * @throws if the device_id can't be resolved, the old broker won't come up, or
 *   the DELETE fails — the caller logs loudly and decides whether to continue.
 */
export async function revokeOldAgentDeviceForReissue({ existing, scope, idpUrl, log = () => {}, deps = {} }) {
  const _deriveAgentKeypair = deps.deriveAgentKeypair ?? deriveAgentKeypair;
  const _revokeAgentDevice = deps.revokeAgentDevice ?? revokeAgentDevice;
  const _startBrokerSupervisor = deps.startBrokerSupervisor ?? startBrokerSupervisor;
  const _resolveAgentDeviceId = deps.resolveAgentDeviceId ?? resolveAgentDeviceId;
  const _brokerAvailable = deps.brokerAvailable ?? brokerAvailable;

  const oldDeviceId = _resolveAgentDeviceId({
    persistedDeviceId: existing.deviceId,
    slotSeed: existing.slotSeed,
    agentDid: existing.agentDid,
  });
  if (!oldDeviceId) {
    throw new Error('reissue revoke: could not resolve the old device_id (no persisted id and no seed)');
  }
  const effIdp = existing.idpUrl ?? idpUrl;
  const haveSeed = Buffer.isBuffer(existing.slotSeed) && existing.slotSeed.length === 32;

  if (haveSeed) {
    // LEGACY: node holds the old seed → mint the DPoP locally.
    const { signingKey } = _deriveAgentKeypair(existing.slotSeed, existing.agentDid);
    await _revokeAgentDevice({
      idpUrl: effIdp,
      deviceId: oldDeviceId,
      agentDid: existing.agentDid,
      vcCompact: existing.vcCompact,
      signingKey,
      scope,
    });
    return oldDeviceId;
  }

  // BROKER-NATIVE: the old key is in the OLD broker's protected store. signingKey
  // is null — authedIdpFetch sees a broker up for this scope and routes the DELETE
  // through it (the broker mints the old-key DPoP).
  //
  // PREFER a broker that is ALREADY up for this scope — the running listener's,
  // agent-mode with the old seed. Revoke through it with NO broker juggling: the
  // caller revokes BEFORE stopping the listener, so its broker is still live.
  // Starting a fresh broker here instead would race the listener-broker's socket
  // teardown — startBrokerSupervisor rm's the socket while the dying broker still
  // holds it, so the new broker reports ready but the path is unlinked →
  // ECONNREFUSED on the revoke (the live-reissue failure we hit).
  if (await _brokerAvailable(scope)) {
    log('[reissue] revoking the old device through the running broker (race-free)…');
    await _revokeAgentDevice({
      idpUrl: effIdp,
      deviceId: oldDeviceId,
      agentDid: existing.agentDid,
      vcCompact: existing.vcCompact,
      signingKey: null, // the broker mints the DPoP from the old seed
      scope,
    });
    return oldDeviceId;
  }

  // No broker up for this scope (cold reissue, no running listener) — start a temp
  // one. There is no competing broker here, so no socket race. Stopped afterwards.
  log('[reissue] no running broker — starting a temp old broker (agent-mode) to revoke…');
  const oldBroker = await _startBrokerSupervisor({
    scope,
    idpUrl: effIdp,
    enabled: true,
    log,
  });
  if (!oldBroker?.ready) {
    oldBroker?.stop?.();
    throw new Error('reissue revoke: the old broker (agent-mode) did not come up to mint the revoke DPoP');
  }
  try {
    await _revokeAgentDevice({
      idpUrl: effIdp,
      deviceId: oldDeviceId,
      agentDid: existing.agentDid,
      vcCompact: existing.vcCompact,
      signingKey: null, // the broker mints the DPoP from the old seed
      scope,
    });
    return oldDeviceId;
  } finally {
    oldBroker.stop?.();
  }
}
