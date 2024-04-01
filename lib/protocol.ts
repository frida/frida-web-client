import * as dbus from "@frida/dbus";

export interface HostConnection {
    bus: dbus.MessageBus;
    session: HostSession;
}

export interface HostSession extends dbus.ClientInterface {
    enumerateProcesses: dbus.ProxyMethod<(options: VariantDict) => Promise<HostProcessInfo[]>>;
    attach: dbus.ProxyMethod<(pid: number, options: VariantDict) => Promise<AgentSessionId>>;
    reattach: dbus.ProxyMethod<(id: AgentSessionId) => Promise<void>>;
}

export interface AgentSession extends dbus.ClientInterface {
    close: dbus.ProxyMethod<() => Promise<void>>;

    resume: dbus.ProxyMethod<(rxBatchId: number) => Promise<number>>;

    createScript: dbus.ProxyMethod<(source: string, options: VariantDict) => Promise<AgentScriptId>>;
    destroyScript: dbus.ProxyMethod<(scriptId: AgentScriptId) => Promise<void>>;
    loadScript: dbus.ProxyMethod<(scriptId: AgentScriptId) => Promise<void>>;
    postMessages: dbus.ProxyMethod<(messages: AgentMessageRecord[], batchId: number) => Promise<void>>;

    offerPeerConnection: dbus.ProxyMethod<(offerSdp: string, options: VariantDict) => Promise<string>>;
    addCandidates: dbus.ProxyMethod<(candidateSdps: string[]) => Promise<void>>;
    notifyCandidateGatheringDone: dbus.ProxyMethod<() => Promise<void>>;
    beginMigration: dbus.ProxyMethod<() => Promise<void>>;
    commitMigration: dbus.ProxyMethod<() => Promise<void>>;
}

export type HostProcessInfo = [pid: number, name: string, parameters: VariantDict];

export type CrashInfo = [pid: number, processName: string, summary: string, report: string, parameters: VariantDict];

export type AgentSessionId = [handle: string];

export type AgentScriptId = [handle: number];

export class AgentMessageSink extends dbus.interface.Interface {
    #handler: AgentMessageHandler;

    constructor(handler: AgentMessageHandler) {
        super("re.frida.AgentMessageSink16");

        this.#handler = handler;
    }

    @dbus.interface.method({ inSignature: "a(i(u)sbay)u" })
    postMessages(messages: AgentMessageRecord[], batchId: number): void {
        this.#handler(messages, batchId);
    }
}

export type AgentMessageHandler = (messages: AgentMessageRecord[], batchId: number) => void;

export type AgentMessageRecord = [kind: number, scriptId: AgentScriptId, text: string, hasData: boolean, data: number[]];

export enum AgentMessageKind {
    Script = 1,
    Debugger
}

export interface VariantDict {
    [name: string]: dbus.Variant;
}
