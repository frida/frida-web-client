import { Crash } from "./crash";
import { Process } from "./process";
import {
    HostSession,
    CrashInfo,
    AgentSession,
    AgentSessionId,
    VariantDict,
} from "./protocol";
import {
    Session,
    SessionDetachReason,
} from "./session";

import * as dbus from "@frida/dbus";
import RTCStream from "@frida/rtc-stream";

export class Client {
    private _serverUrl: string;

    private _hostSessionRequest: Promise<HostSession> | null = null;
    private _currentBus: dbus.MessageBus | null = null;

    private _sessions = new Map<string, Session>();

    constructor(host: string, options: ClientOptions = {}) {
        let scheme;
        const { tls = "auto" } = options;
        switch (tls) {
            case "auto":
                scheme = (location.protocol === ":https") ? "wss" : "ws";
                break;
            case "enabled":
                scheme = "wss";
                break;
            case "disabled":
                scheme = "ws";
                break;
        }
        this._serverUrl = `${scheme}://${host}/ws`;
    }

    async enumerateProcesses(options: ProcessQueryOptions = {}): Promise<Process[]> {
        const hostSession = await this.getHostSession();

        const rawOptions: VariantDict = {};
        const { pids, scope } = options;
        if (pids !== undefined) {
            rawOptions.pids = new dbus.Variant("au", pids);
        }
        if (scope !== undefined) {
            rawOptions.scope = new dbus.Variant("s", scope);
        }

        const rawProcesses = await hostSession.enumerateProcesses(rawOptions);

        return rawProcesses.map(([pid, name, parameters]) => {
            return { pid, name, parameters };
        });
    }

    async attach(pid: number, options: SessionOptions = {}): Promise<Session> {
        const hostSession = await this.getHostSession();
        const bus = this._currentBus!;

        const rawOptions: VariantDict = {};
        const { realm, persistTimeout } = options;
        if (realm !== undefined) {
            rawOptions.realm = new dbus.Variant("s", realm);
        }
        if (persistTimeout !== undefined) {
            rawOptions["persist-timeout"] = new dbus.Variant("u", persistTimeout);
        }

        const sessionId = await hostSession.attach(pid, rawOptions);

        const agentSessionObj = await bus.getProxyObject("re.frida.AgentSession15", "/re/frida/AgentSession/" + sessionId[0])
        const agentSession = agentSessionObj.getInterface("re.frida.AgentSession15") as AgentSession;

        const session = new Session(agentSession, sessionId, bus);
        this._sessions.set(sessionId[0], session);

        return session;
    }

    private async getHostSession(): Promise<HostSession> {
        if (this._hostSessionRequest === null) {
            this._hostSessionRequest = this._getHostSession();
        }
        return this._hostSessionRequest;
    }

    private async _getHostSession(): Promise<HostSession> {
        let hostSession: HostSession | null = null;

        const ws = RTCStream.from(new WebSocket(this._serverUrl));
        ws.once("close", () => {
            for (const session of this._sessions.values()) {
                session._destroy(SessionDetachReason.ConnectionTerminated, null);
            }

            this._hostSessionRequest = null;
            this._currentBus = null;
        });

        const bus = dbus.peerBus(ws, {
            authMethods: [],
        });
        bus.once("error", () => {
            // Ignore
        });

        const hostSessionObj = await bus.getProxyObject("re.frida.HostSession15", "/re/frida/HostSession");
        hostSession = hostSessionObj.getInterface("re.frida.HostSession15") as HostSession;

        this._currentBus = bus;

        hostSession.on("agentSessionDetached", this._onAgentSessionDetached);

        return hostSession;
    }

    private _onAgentSessionDetached = (id: AgentSessionId, reason: SessionDetachReason, rawCrash: CrashInfo): void => {
        const session = this._sessions.get(id[0]);
        if (session === undefined) {
            return;
        }

        const [pid, processName, summary, report, parameters] = rawCrash;
        const crash: Crash | null = (pid !== 0)
            ? { pid, processName, summary, report, parameters }
            : null;

        session._destroy(reason, crash);
    };
}

export interface ClientOptions {
    tls?: TransportLayerSecurity;
}

export enum TransportLayerSecurity {
    Auto = "auto",
    Disabled = "disabled",
    Enabled = "enabled"
}

export interface ProcessQueryOptions {
    pids?: number[];
    scope?: Scope;
}

export enum Scope {
    Minimal = "minimal",
    Metadata = "metadata",
    Full = "full"
}

export interface SessionOptions {
    realm?: Realm;
    persistTimeout?: number;
}

export enum Realm {
    Native = "native",
    Emulated = "emulated"
}
