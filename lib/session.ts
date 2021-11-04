import {
    HostConnection,
    AgentSession,
    AgentSessionId,
    AgentMessageSink,
    AgentMessageHandler,
    AgentMessageRecord,
    AgentMessageKind,
    VariantDict,
} from "./protocol";
import { Crash } from "./crash";
import { Script, ScriptOptions } from "./script";
import { Signal } from "./signals";

import { EventEmitter } from "events";
import * as dbus from "@frida/dbus";
import RTCStream from "@frida/rtc-stream";

export class Session {
    detached: Signal<SessionDetachedHandler>;

    _events = new EventEmitter();

    _activeSession: AgentSession;
    private _obsoleteSession: AgentSession | null = null;
    private _state: "attached" | "interrupted" | "detached" = "attached";

    private readonly _sink: AgentMessageSink;
    private _lastRxBatchId = 0;
    private _pendingMessages: PendingMessage[] = [];
    private _nextSerial = 1;
    private _pendingDeliveries = 0;

    private readonly _scripts = new Map<number, Script>();

    private _peerConnection: RTCPeerConnection | null = null;
    private _peerOptions: PeerOptions | null = null;

    constructor(
            private _controller: SessionController,
            session: AgentSession,
            public pid: number,
            public id: string,
            public persistTimeout: number,
            connection: HostConnection) {
        this._activeSession = session;
        this._sink = new AgentMessageSink(this._dispatchMessages);

        this.detached = new Signal<SessionDetachedHandler>(this._events, "detached");

        connection.bus.export("/re/frida/AgentMessageSink/" + id, this._sink);
    }

    get isDetached(): boolean {
        return this._state !== "attached";
    }

    detach(): void {
        this._destroy(SessionDetachReason.ApplicationRequested, null);
    }

    async resume(): Promise<void> {
        switch (this._state) {
            case "attached":
                return;
            case "interrupted":
                break;
            case "detached":
                throw new Error("session is gone");
        }

        const connection = await this._controller._getHostConnection();

        const rawId: AgentSessionId = [this.id];

        await connection.session.reattach(rawId);

        const agentSession = await this._controller._linkAgentSession(rawId, connection);

        this._beginMigration(agentSession);

        if (this._peerOptions !== null) {
            await this.setupPeerConnection(this._peerOptions);
        }

        const lastTxBatchId = await this._activeSession.resume(this._lastRxBatchId);

        if (lastTxBatchId !== 0) {
            let m: PendingMessage | undefined;
            while ((m = this._pendingMessages[0]) !== undefined && m.deliveryAttempts > 0 && m.serial <= lastTxBatchId) {
                this._pendingMessages.shift();
            }
        }

        this._state = "attached";

        this._maybeDeliverPendingMessages();
    }

    async createScript(source: string, options: ScriptOptions = {}): Promise<Script> {
        const rawOptions: VariantDict = {};
        const { name, runtime } = options;
        if (name !== undefined) {
            rawOptions.name = new dbus.Variant("s", name);
        }
        if (runtime !== undefined) {
            rawOptions.runtime = new dbus.Variant("s", runtime);
        }

        const scriptId = await this._activeSession.createScript(source, rawOptions);

        const script = new Script(this, scriptId);
        const onScriptDestroyed = () => {
            this._scripts.delete(scriptId[0]);
            script.destroyed.disconnect(onScriptDestroyed);
        };
        script.destroyed.connect(onScriptDestroyed);
        this._scripts.set(scriptId[0], script);

        return script;
    }

    async setupPeerConnection(options: PeerOptions = {}): Promise<void> {
        const { stunServer, relays } = options;
        const iceServers: RTCIceServer[] = [];
        const rawOptions: VariantDict = {};
        if (stunServer !== undefined) {
            iceServers.push({ urls: makeStunUrl(stunServer) });
            rawOptions["stun-server"] = new dbus.Variant("s", stunServer);
        }
        if (relays !== undefined) {
            iceServers.push(...relays.map(({ address, username, password, kind }) => {
                return {
                    urls: makeTurnUrl(address, kind),
                    username,
                    credential: password
                };
            }));
            rawOptions["relays"] = new dbus.Variant("a(sssu)",
                relays.map(({ address, username, password, kind }) => [address, username, password, kind]));
        }

        const serverSession = this._activeSession;

        const peerConnection = new RTCPeerConnection({ iceServers });

        peerConnection.oniceconnectionstatechange = () => {
            if (peerConnection.iceConnectionState === "disconnected") {
                if (onError !== null) {
                    onError!(new Error(("Unable to establish peer connection")));
                    onError = null;
                    onReady = null;
                }

                this._handlePeerConnectionClosure(peerConnection);
            }
        };

        const pendingLocalCandidates = new IceCandidateQueue();
        pendingLocalCandidates.on("add", (candidates: RTCIceCandidate[]) => {
            serverSession.addCandidates(candidates.map(c => "a=" + c.candidate));
        });
        pendingLocalCandidates.once("done", () => {
            serverSession.notifyCandidateGatheringDone();
        });

        const pendingRemoteCandidates = new IceCandidateQueue();
        pendingRemoteCandidates.on("add", (candidates: RTCIceCandidate[]) => {
            for (const candidate of candidates) {
                peerConnection.addIceCandidate(candidate);
            }
        });
        pendingRemoteCandidates.once("done", () => {
            peerConnection.addIceCandidate(new RTCIceCandidate({
                candidate: "",
                sdpMid: "0",
                sdpMLineIndex: 0
            }));
        });

        peerConnection.onicecandidate = e => {
            pendingLocalCandidates.add(e.candidate);
        };
        serverSession.on("newCandidates", (sdps: string[]) => {
            for (const sdp of sdps) {
                pendingRemoteCandidates.add(new RTCIceCandidate({
                    candidate: sdp.substr(2),
                    sdpMid: "0",
                    sdpMLineIndex: 0
                }));
            }
        });
        serverSession.on("candidateGatheringDone", () => {
            pendingRemoteCandidates.add(null);
        });

        let onReady: ((value: void) => void) | null = null;
        let onError: ((error: Error) => void) | null = null;
        const ready = new Promise<void>((resolve, reject) => {
            onReady = resolve;
            onError = reject;
        });

        const peerChannel = peerConnection.createDataChannel("session");
        peerChannel.onopen = async () => {
            let peerAgentSession: AgentSession | null = null;
            let migrating = false;
            try {
                const peerBus = dbus.peerBus(RTCStream.from(peerChannel), {
                    authMethods: [],
                });

                const peerAgentSessionObj = await peerBus.getProxyObject("re.frida.AgentSession15", "/re/frida/AgentSession");
                peerAgentSession = peerAgentSessionObj.getInterface("re.frida.AgentSession15") as AgentSession;

                peerBus.export("/re/frida/AgentMessageSink", this._sink);

                await serverSession.beginMigration();

                this._beginMigration(peerAgentSession);
                migrating = true;

                await serverSession.commitMigration();

                this._peerConnection = peerConnection;
                this._peerOptions = options;

                if (onReady !== null) {
                    onReady!();
                    onReady = null;
                    onError = null;
                }
            } catch (e) {
                if (migrating) {
                    this._cancelMigration(peerAgentSession!);
                }

                if (onError !== null) {
                    onError!(e as Error);
                    onError = null;
                    onReady = null;
                }
            }
        };
        peerChannel.onerror = event => {
            if (onError !== null) {
                onError!(new Error((event as any).message));
                onError = null;
                onReady = null;
            }
        };
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);

        const answerSdp = await serverSession.offerPeerConnection(offer.sdp!, rawOptions);
        const answer = new RTCSessionDescription({ type: "answer", sdp: answerSdp });
        await peerConnection.setRemoteDescription(answer);

        pendingLocalCandidates.notifySessionStarted();
        pendingRemoteCandidates.notifySessionStarted();

        await ready;
    }

    private _handlePeerConnectionClosure(peerConnection: RTCPeerConnection): void {
        if (peerConnection !== this._peerConnection) {
            return;
        }
        this._peerConnection = null;

        if (this.persistTimeout !== 0) {
            if (this._state !== "attached") {
                return;
            }
            this._state = "interrupted";
            this._activeSession = this._obsoleteSession!;
            this._obsoleteSession = null;
            this._events.emit("detached", SessionDetachReason.ConnectionTerminated, null);
        } else {
            this._destroy(SessionDetachReason.ConnectionTerminated, null);
        }
    }

    private _dispatchMessages: AgentMessageHandler = (messages, batchId): void => {
        for (const [kind, scriptId, text, hasData, data] of messages) {
            if (kind != AgentMessageKind.Script) {
                continue;
            }

            const script = this._scripts.get(scriptId[0]);
            if (script === undefined) {
                continue;
            }

            script._dispatchMessage(JSON.parse(text), hasData ? Buffer.from(data) : null);
        }

        this._lastRxBatchId = batchId;
    };

    _postToAgent(record: AgentMessageRecord): void {
        if (this._state === "detached") {
            return;
        }

        this._pendingMessages.push({
            serial: this._nextSerial++,
            deliveryAttempts: 0,
            record,
        });
        this._maybeDeliverPendingMessages();
    }

    private _maybeDeliverPendingMessages(): void {
        if (this._state !== "attached") {
            return;
        }

        if (this._pendingMessages.length === 0) {
            return;
        }

        const batch: PendingMessage[] = [];
        let message: PendingMessage | undefined;
        let totalSize = 0;
        const maxSize = 4 * 1024 * 1024;
        while ((message = this._pendingMessages.shift()) !== undefined) {
            const { record } = message;
            const text = record[2];
            const data = record[4];
            const messageSizeEstimate = text.length + data.length;
            if (totalSize + messageSizeEstimate > maxSize && batch.length !== 0) {
                break;
            }

            batch.push(message);

            totalSize += messageSizeEstimate;
        }

        if (this.persistTimeout === 0) {
            this._emitBatch(batch);
        } else {
            this._deliverBatch(batch);
        }
    }

    private _emitBatch(messages: PendingMessage[]): void {
        this._activeSession.postMessages.begin(messages.map(m => m.record), 0);
    }

    private async _deliverBatch(messages: PendingMessage[]): Promise<void> {
        let success = false;
        this._pendingDeliveries++;
        try {
            for (const message of messages) {
                message.deliveryAttempts++;
            }

            const batchId = messages[messages.length - 1].serial;

            await this._activeSession.postMessages(messages.map(m => m.record), batchId);

            success = true;
        } catch (e) {
            this._pendingMessages.push(...messages);
            this._pendingMessages.sort((a, b) => a.serial - b.serial);
        } finally {
            this._pendingDeliveries--;
            if (this._pendingDeliveries === 0 && success) {
                this._nextSerial = 1;
            }
        }
    }

    _onDetached(reason: SessionDetachReason, crash: Crash | null): void {
        if (this.persistTimeout !== 0 && reason === SessionDetachReason.ConnectionTerminated) {
            if (this._state !== "attached") {
                return;
            }
            this._state = "interrupted";
            this._events.emit("detached", reason, null);
        } else {
            this._destroy(reason, crash);
        }
    }

    _destroy(reason: SessionDetachReason, crash: Crash | null): void {
        if (this._state === "detached") {
            return;
        }
        this._state = "detached";

        for (const script of this._scripts.values()) {
            script._destroy();
        }

        this._closeSessionAndPeerConnection(reason);

        this._events.emit("detached", reason, crash);
        this._events.emit("destroyed");
    }

    async _closeSessionAndPeerConnection(reason: SessionDetachReason): Promise<void> {
        if (reason === SessionDetachReason.ApplicationRequested) {
            try {
                await this._activeSession.close();
            } catch (e) {
            }
        }

        const peerConnection = this._peerConnection;
        if (peerConnection !== null) {
            this._peerConnection = null;
            peerConnection.close();
        }
    }

    _beginMigration(newSession: AgentSession): void {
        this._obsoleteSession = this._activeSession;
        this._activeSession = newSession;
    }

    _cancelMigration(newSession: AgentSession): void {
        this._activeSession = this._obsoleteSession!;
        this._obsoleteSession = null;
    }
}

export type SessionDetachedHandler = (reason: SessionDetachReason, crash: Crash | null) => void;

export enum SessionDetachReason {
    ApplicationRequested = 1,
    ProcessReplaced,
    ProcessTerminated,
    ConnectionTerminated,
    DeviceLost,
}

export interface PeerOptions {
    stunServer?: string;
    relays?: Relay[];
}

export interface Relay {
    address: string;
    username: string;
    password: string;
    kind: RelayKind;
}

export enum RelayKind {
    TurnUDP = 0,
    TurnTCP,
    TurnTLS,
}

export interface SessionController {
    _getHostConnection(): Promise<HostConnection>;
    _linkAgentSession(id: AgentSessionId, connection: HostConnection): Promise<AgentSession>;
}

interface PendingMessage {
    serial: number;
    deliveryAttempts: number;
    record: AgentMessageRecord;
}

function makeStunUrl(address: string): string {
    return `stun:${address}?transport=udp`
}

function makeTurnUrl(address: string, kind: RelayKind): string {
    switch (kind) {
        case RelayKind.TurnUDP:
            return `turn:${address}?transport=udp`;
        case RelayKind.TurnTCP:
            return `turn:${address}?transport=tcp`;
        case RelayKind.TurnTLS:
            return `turns:${address}?transport=tcp`;
    }
}

class IceCandidateQueue extends EventEmitter {
    private sessionState: "starting" | "started" = "starting";
    private gatheringState: "gathering" | "gathered" | "notified" = "gathering";
    private pending: RTCIceCandidate[] = [];
    private timer: NodeJS.Timeout | null = null;

    add(candidate: RTCIceCandidate | null) {
        if (candidate !== null) {
            this.pending.push(candidate);
        } else {
            this.gatheringState = "gathered";
        }

        if (this.timer === null) {
            this.timer = setTimeout(this.maybeEmitCandidates, 10);
        }
    }

    notifySessionStarted() {
        this.sessionState = "started";

        if (this.timer !== null) {
            clearTimeout(this.timer);
            this.timer = null;
        }

        this.maybeEmitCandidates();
    }

    private maybeEmitCandidates = () => {
        this.timer = null;

        if (this.sessionState !== "started") {
            return;
        }

        if (this.pending.length > 0) {
            this.emit("add", this.pending.splice(0));
        }

        if (this.gatheringState === "gathered") {
            this.emit("done");
            this.gatheringState = "notified";
        }
    };
}
