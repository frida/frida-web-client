import {
    AgentSession,
    AgentSessionId,
    AgentMessageSink,
    AgentMessageHandler,
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

    private _handle: AgentSession;
    private readonly _scripts = new Map<number, Script>();
    private readonly _sink;

    private _peerBus: dbus.MessageBus | null = null;

    constructor(handle: AgentSession, id: AgentSessionId, bus: dbus.MessageBus) {
        this._handle = handle;
        this._sink = new AgentMessageSink(this.dispatchMessages);

        this.detached = new Signal<SessionDetachedHandler>(handle, "detached");

        bus.export("/re/frida/AgentMessageSink/" + id[0], this._sink);
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

        const scriptId = await this._handle.createScript(source, rawOptions);

        const script = new Script(scriptId, this._handle);
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
            iceServers.push({ urls: "stun:" + stunServer });
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

        const agentSession = this._handle;

        await agentSession.beginMigration();

        const peerConnection = new RTCPeerConnection({ iceServers });

        const pendingLocalCandidates = new IceCandidateQueue();
        pendingLocalCandidates.on("add", (candidates: RTCIceCandidate[]) => {
            agentSession.addCandidates(candidates.map(c => c.candidate));
        });
        pendingLocalCandidates.once("done", () => {
            agentSession.notifyCandidateGatheringDone();
        });

        const pendingRemoteCandidates = new IceCandidateQueue();
        pendingRemoteCandidates.on("add", candidates => {
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
        agentSession.on("newCandidates", (sdps: string[]) => {
            for (const sdp of sdps) {
                pendingRemoteCandidates.add(new RTCIceCandidate({
                    candidate: sdp,
                    sdpMid: "0",
                    sdpMLineIndex: 0
                }));
            }
        });
        agentSession.on("candidateGatheringDone", () => {
            pendingRemoteCandidates.add(null);
        });

        let onReady: ((value: void) => void) | null = null;
        let onError: ((error: Error) => void) | null = null;
        const ready = new Promise<void>((resolve, reject) => {
            onReady = resolve;
            onError = reject;
        });

        const peerChannel = peerConnection.createDataChannel("session");
        peerChannel.onopen = async event => {
            const peerBus = dbus.peerBus(RTCStream.from(peerChannel), {
                authMethods: [],
            });
            this._peerBus = peerBus;

            const peerAgentSessionObj = await peerBus.getProxyObject("re.frida.AgentSession15", "/re/frida/AgentSession");
            const peerAgentSession = peerAgentSessionObj.getInterface("re.frida.AgentSession15") as AgentSession;

            peerBus.export("/re/frida/AgentMessageSink", this._sink);

            await agentSession.commitMigration();

            this._handle = peerAgentSession;

            onReady!();
            onReady = null;
            onError = null;
        };
        peerChannel.onclose = event => {
            // TODO: Wire up
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

        const answerSdp = await agentSession.offerPeerConnection(offer.sdp!, rawOptions);
        const answer = new RTCSessionDescription({ type: "answer", sdp: answerSdp });
        await peerConnection.setRemoteDescription(answer);

        pendingLocalCandidates.notifySessionStarted();
        pendingRemoteCandidates.notifySessionStarted();

        await ready;
    }

    private dispatchMessages: AgentMessageHandler = (messages, batchId): void => {
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
    };

    _destroy(reason: SessionDetachReason, crash: Crash | null) {
        for (const script of this._scripts.values()) {
            script._destroy();
        }

        this._handle.emit("detached", reason, crash);
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

function makeTurnUrl(address: string, kind: RelayKind): string {
    switch (kind) {
        case RelayKind.TurnUDP:
            return `turn:${address}`;
        case RelayKind.TurnTCP:
            return `turn:${address}?transport=tcp`;
        case RelayKind.TurnTLS:
            return `turns:${address}`;
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
