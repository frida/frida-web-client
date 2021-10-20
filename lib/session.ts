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

import * as dbus from "@frida/dbus";

export class Session {
    detached: Signal<SessionDetachedHandler>;

    private _handle: AgentSession;
    private _scripts = new Map<number, Script>();

    constructor(handle: AgentSession, id: AgentSessionId, bus: dbus.MessageBus) {
        this._handle = handle;

        this.detached = new Signal<SessionDetachedHandler>(handle, "detached");

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
        const onScriptDestroyed = () => {
            this._scripts.delete(scriptId[0]);
            script.destroyed.disconnect(onScriptDestroyed);
        };
        script.destroyed.connect(onScriptDestroyed);
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
