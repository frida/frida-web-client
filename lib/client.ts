import { Crash } from "./crash";
import { Process } from "./process";
import {
    HostConnection,
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
    private readonly _serverUrl: string;

    private _hostConnectionRequest: Promise<HostConnection> | null = null;

    private readonly _sessions = new Map<string, Session>();

    constructor(host: string, options: ClientOptions = {}) {
        let scheme;
        const { tls = "auto" } = options;
        switch (tls) {
            case "auto":
                scheme = (typeof location !== "undefined" && location.protocol === "https:") ? "wss" : "ws";
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
        const connection = await this._getHostConnection();

        const rawOptions: VariantDict = {};
        const { pids, scope } = options;
        if (pids !== undefined) {
            rawOptions.pids = new dbus.Variant("au", pids);
        }
        if (scope !== undefined) {
            rawOptions.scope = new dbus.Variant("s", scope);
        }

        const rawProcesses = await connection.session.enumerateProcesses(rawOptions);

        return rawProcesses.map(([pid, name, parameters]) => {
            return { pid, name, parameters };
        });
    }

    async attach(pid: number, options: SessionOptions = {}): Promise<Session> {
        const connection = await this._getHostConnection();

        const rawOptions: VariantDict = {};
        const { realm, persistTimeout } = options;
        if (realm !== undefined) {
            rawOptions.realm = new dbus.Variant("s", realm);
        }
        if (persistTimeout !== undefined) {
            rawOptions["persist-timeout"] = new dbus.Variant("u", persistTimeout);
        }

        const sessionId = await connection.session.attach(pid, rawOptions);

        const agentSession = await this._linkAgentSession(sessionId, connection);

        const session = new Session(this, agentSession, pid, sessionId[0], persistTimeout ?? 0, connection);
        this._sessions.set(session.id, session);
        session._events.once("destroyed", () => {
            this._sessions.delete(session.id);
        });

        return session;
    }

    async _getHostConnection(): Promise<HostConnection> {
        if (this._hostConnectionRequest === null) {
            this._hostConnectionRequest = this._doGetHostConnection();
        }
        return this._hostConnectionRequest;
    }

    private async _doGetHostConnection(): Promise<HostConnection> {
        const ws = RTCStream.from(new WebSocket(this._serverUrl));
        ws.once("close", () => {
            this._hostConnectionRequest = null;

            for (const session of this._sessions.values()) {
                session._onDetached(SessionDetachReason.ConnectionTerminated, null);
            }
        });

        const bus = dbus.peerBus(ws, {
            authMethods: [],
        });
        bus.once("error", () => {
            // Ignore
        });

        const sessionObj = await bus.getProxyObject("re.frida.HostSession16", "/re/frida/HostSession");
        const session = sessionObj.getInterface("re.frida.HostSession16") as HostSession;

        session.on("agentSessionDetached", this._onAgentSessionDetached);

        return { bus, session };
    }

    async _linkAgentSession(id: AgentSessionId, connection: HostConnection): Promise<AgentSession> {
        const agentSessionObj = await connection.bus.getProxyObject("re.frida.AgentSession16", "/re/frida/AgentSession/" + id[0]);
        return agentSessionObj.getInterface("re.frida.AgentSession16") as AgentSession;
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

        session._onDetached(reason, crash);
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
