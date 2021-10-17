import * as dbus from "@frida/dbus";
import RTCStream from "@frida/rtc-stream";
import { Buffer } from "buffer";
import { EventEmitter } from "events";
import TypedEmitter from "typed-emitter";

const {
    Interface,
    method,
} = dbus.interface;

export class Client {
    private _serverUrl: string;

    private _hostSessionRequest: Promise<HostSession> | null = null;
    private _currentHostSession: HostSession | null = null;
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
            if (this._currentHostSession === hostSession) {
                for (const session of this._sessions.values()) {
                    session._destroy(SessionDetachReason.ConnectionTerminated, null);
                }

                this._hostSessionRequest = null;
                this._currentHostSession = null;
                this._currentBus = null;
            }
        });

        const bus = dbus.peerBus(ws, {
            authMethods: [],
        });
        bus.once("error", () => {
            // Ignore
        });

        const hostSessionObj = await bus.getProxyObject("re.frida.HostSession15", "/re/frida/HostSession");
        hostSession = hostSessionObj.getInterface("re.frida.HostSession15") as HostSession;

        this._currentHostSession = hostSession;
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

export interface Process {
    pid: number;
    name: string;
    parameters: VariantDict;
}

export interface SessionOptions {
    realm?: Realm;
    persistTimeout?: number;
}

export enum Realm {
    Native = "native",
    Emulated = "emulated"
}

export class Session {
    events = new EventEmitter() as TypedEmitter<SessionEvents>;

    private _handle: AgentSession;
    private _scripts = new Map<number, Script>();

    constructor(handle: AgentSession, id: AgentSessionId, bus: dbus.MessageBus) {
        this._handle = handle;

        bus.export("/re/frida/AgentMessageSink/" + id[0], new AgentMessageSink(this.dispatchMessages));
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
        script.events.once("destroy", () => {
            this._scripts.delete(scriptId[0]);
        });
        this._scripts.set(scriptId[0], script);

        return script;
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

        this.events.emit("detach", reason, crash);
    }
}

export interface SessionEvents {
    detach(reason: SessionDetachReason, crash: Crash | null): void;
}

export enum SessionDetachReason {
    ApplicationRequested = 1,
    ProcessReplaced,
    ProcessTerminated,
    ConnectionTerminated,
    DeviceLost,
}

export interface Crash {
    pid: number;
    processName: string;
    summary: string;
    report: string;
    parameters: VariantDict;
}

export class Script {
    events = new EventEmitter() as TypedEmitter<ScriptEvents>;

    private _id: AgentScriptId;
    private _agentSession: AgentSession;

    constructor(id: AgentScriptId, agentSession: AgentSession) {
        this._id = id;
        this._agentSession = agentSession;
    }

    load(): Promise<void> {
        return this._agentSession.loadScript(this._id);
    }

    async unload(): Promise<void> {
        await this._agentSession.destroyScript(this._id);

        this.events.emit("destroy");
    }

    post(message: any, data: Buffer | null = null): void {
        const hasData = data !== null;
        const rawMessage: AgentMessageRecord = [
            AgentMessageKind.Script,
            this._id,
            JSON.stringify(message),
            hasData,
            []
        ];
        this._agentSession.postMessages([rawMessage], 0).catch(noop);
    }

    _destroy() {
        this.events.emit("destroy");
    }

    _dispatchMessage(message: Message, data: Buffer | null): void {
        this.events.emit("message", message, data);
    }
}

export interface ScriptEvents {
    destroy(): void;
    message(message: Message, data: Buffer | null): void;
}

export interface ScriptOptions {
    name?: string;
    runtime?: ScriptRuntime;
}

export enum ScriptRuntime {
    Default = "default",
    QJS = "qjs",
    V8 = "v8",
}

export type Message = SendMessage | ErrorMessage;

export enum MessageType {
    Send = "send",
    Error = "error",
    Log = "log",
}

export interface SendMessage {
    type: MessageType.Send;
    payload: any;
}

export interface ErrorMessage {
    type: MessageType.Error;
    description: string;
    stack?: string;
    fileName?: string;
    lineNumber?: number;
    columnNumber?: number;
}

export interface VariantDict {
    [name: string]: dbus.Variant;
}

interface HostSession extends dbus.ClientInterface {
    enumerateProcesses(options: VariantDict): Promise<HostProcessInfo[]>;
    attach(pid: number, options: VariantDict): Promise<AgentSessionId>;
}

interface AgentSession extends dbus.ClientInterface {
    createScript(source: string, options: VariantDict): Promise<AgentScriptId>;
    destroyScript(scriptId: AgentScriptId): Promise<void>;
    loadScript(scriptId: AgentScriptId): Promise<void>;
    postMessages(messages: AgentMessageRecord[], batchId: number): Promise<void>;
}

type HostProcessInfo = [pid: number, name: string, parameters: VariantDict];

type CrashInfo = [pid: number, processName: string, summary: string, report: string, parameters: VariantDict];

type AgentSessionId = [handle: string];

type AgentScriptId = [handle: number];

class AgentMessageSink extends Interface {
    #handler: AgentMessageHandler;

    constructor(handler: AgentMessageHandler) {
        super("re.frida.AgentMessageSink15");

        this.#handler = handler;
    }

    @method({ inSignature: "a(i(u)sbay)u" })
    postMessages(messages: AgentMessageRecord[], batchId: number): void {
        this.#handler(messages, batchId);
    }
}

type AgentMessageHandler = (messages: AgentMessageRecord[], batchId: number) => void;

type AgentMessageRecord = [kind: number, scriptId: AgentScriptId, text: string, hasData: boolean, data: number[]];

enum AgentMessageKind {
    Script = 1,
    Debugger
}

function noop() {
}
