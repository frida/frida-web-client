import * as dbus from "@frida/dbus";

export interface HostSession extends dbus.ClientInterface {
    enumerateProcesses(options: VariantDict): Promise<HostProcessInfo[]>;
    attach(pid: number, options: VariantDict): Promise<AgentSessionId>;
}

export interface AgentSession extends dbus.ClientInterface {
    createScript(source: string, options: VariantDict): Promise<AgentScriptId>;
    destroyScript(scriptId: AgentScriptId): Promise<void>;
    loadScript(scriptId: AgentScriptId): Promise<void>;
    postMessages(messages: AgentMessageRecord[], batchId: number): Promise<void>;

    offerPeerConnection(offerSdp: string, options: VariantDict): Promise<string>;
    addCandidates(candidateSdps: string[]): Promise<void>;
    notifyCandidateGatheringDone(): Promise<void>;
    beginMigration(): Promise<void>;
    commitMigration(): Promise<void>;
}

export type HostProcessInfo = [pid: number, name: string, parameters: VariantDict];

export type CrashInfo = [pid: number, processName: string, summary: string, report: string, parameters: VariantDict];

export type AgentSessionId = [handle: string];

export type AgentScriptId = [handle: number];

export class AgentMessageSink extends dbus.interface.Interface {
    #handler: AgentMessageHandler;

    constructor(handler: AgentMessageHandler) {
        super("re.frida.AgentMessageSink15");

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
