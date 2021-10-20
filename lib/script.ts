import {
    AgentSession,
    AgentScriptId,
    AgentMessageRecord,
    AgentMessageKind,
} from "./protocol";
import {
    SignalSource,
    Signal,
    SignalHandler,
    SignalAdapter,
} from "./signals";

import { EventEmitter } from "events";
import { inspect } from "util";

export class Script {
    destroyed: Signal<ScriptDestroyedHandler>;
    message: Signal<ScriptMessageHandler>;

    private _id: AgentScriptId;
    private _agentSession: AgentSession;
    private _state: "created" | "destroyed" = "created";
    private _exportsProxy: ScriptExports;
    private _logHandlerImpl: ScriptLogHandler = log;

    constructor(id: AgentScriptId, agentSession: AgentSession) {
        this._id = id;
        this._agentSession = agentSession;

        const services = new ScriptServices(this, agentSession);

        const rpcController: RpcController = services;
        this._exportsProxy = makeScriptExportsProxy(rpcController);

        const source: SignalSource = services;
        this.destroyed = new Signal<ScriptDestroyedHandler>(source, "destroyed");
        this.message = new Signal<ScriptMessageHandler>(source, "message");
    }

    get isDestroyed(): boolean {
        return this._state === "destroyed";
    }

    get exports(): ScriptExports {
        return this._exportsProxy;
    }

    get logHandler(): ScriptLogHandler {
        return this._logHandlerImpl;
    }

    set logHandler(handler: ScriptLogHandler) {
        this._logHandlerImpl = handler;
    }

    get defaultLogHandler(): ScriptLogHandler {
        return log;
    }

    load(): Promise<void> {
        return this._agentSession.loadScript(this._id);
    }

    async unload(): Promise<void> {
        await this._agentSession.destroyScript(this._id);

        this._destroy();
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
        if (this._state === "destroyed") {
            return;
        }

        this._state = "destroyed";
        this._agentSession.emit("destroyed");
    }

    _dispatchMessage(message: Message, data: Buffer | null): void {
        this._agentSession.emit("message", message, data);
    }
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

export type ScriptDestroyedHandler = () => void;
export type ScriptMessageHandler = (message: Message, data: Buffer | null) => void;
export type ScriptLogHandler = (level: LogLevel, text: string) => void;

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

interface LogMessage {
    type: "log";
    level: LogLevel;
    payload: string;
}

export interface ScriptExports {
    [name: string]: (...args: any[]) => Promise<any>;
}

export enum LogLevel {
    Info = "info",
    Warning = "warning",
    Error = "error"
}

class ScriptServices extends SignalAdapter implements RpcController {
    private pendingRequests: { [id: string]: (error: Error | null, result?: any) => void } = {};
    private nextRequestId: number = 1;

    constructor(private script: Script, events: EventEmitter) {
        super(events);

        this.signalSource.addListener("destroyed", this.onDestroyed);
        this.signalSource.addListener("message", this.onMessage);
    }

    protected getProxy(name: string, userHandler: SignalHandler): SignalHandler | null {
        if (name === "message") {
            return (message, data) => {
                if (!isInternalMessage(message)) {
                    userHandler(message, data);
                }
            };
        }

        return null;
    }

    private onDestroyed = () => {
        this.signalSource.removeListener("destroyed", this.onDestroyed);
        this.signalSource.removeListener("message", this.onMessage);
    }

    private onMessage = (message: Message, data: Buffer | null) => {
        if (message.type === MessageType.Send && isRpcSendMessage(message)) {
            const [, id, operation, ...params] = message.payload;
            this.onRpcMessage(id, operation, params, data);
        } else if (isLogMessage(message)) {
            const opaqueMessage: any = message;
            const logMessage: LogMessage = opaqueMessage;
            this.script.logHandler(logMessage.level, logMessage.payload);
        }
    }

    request(operation: string, params: any[]): Promise<any> {
        return new Promise((resolve, reject) => {
            const id = this.nextRequestId++;

            const complete = (error: Error | null, result?: any): void => {
                this.signalSource.removeListener("destroyed", onScriptDestroyed);

                delete this.pendingRequests[id];

                if (error === null) {
                    resolve(result);
                } else {
                    reject(error);
                }
            };

            function onScriptDestroyed(): void {
                complete(new Error("Script is destroyed"));
            }

            this.pendingRequests[id] = complete;

            this.script.post(["frida:rpc", id, operation].concat(params));
            this.signalSource.addListener("destroyed", onScriptDestroyed);
            if (this.script.isDestroyed) {
                onScriptDestroyed();
            }
        });
    }

    onRpcMessage(id: number, operation: RpcOperation, params: any[], data: Buffer | null) {
        if (operation === RpcOperation.Ok || operation === RpcOperation.Error) {
            const callback = this.pendingRequests[id];
            if (callback === undefined) {
                return;
            }

            let value = null;
            let error = null;
            if (operation === RpcOperation.Ok) {
                value = (data !== null) ? data : params[0];
            } else {
                const [message, name, stack, properties] = params;
                error = new Error(message);
                error.name = name;
                error.stack = stack;
                Object.assign(error, properties);
            }

            callback(error, value);
        }
    }
}

function makeScriptExportsProxy(rpcController: RpcController): ScriptExports {
    return new Proxy({} as ScriptExports, {
        has(target, property) {
            return !isReservedMethodName(property);;
        },
        get(target, property, receiver) {
            if (property in target && typeof property === "string") {
                return target[property];
            }

            if (property === inspect.custom) {
                return inspectProxy;
            }

            if (isReservedMethodName(property)) {
                return undefined;
            }

            return (...args: any[]): Promise<any> => {
                return rpcController.request("call", [property, args]);
            };
        },
        set(target, property, value, receiver) {
            if (typeof property !== "string") {
                return false;
            }
            target[property] = value;
            return true;
        },
        ownKeys(target) {
            return Object.getOwnPropertyNames(target);
        },
        getOwnPropertyDescriptor(target, property) {
            if (property in target) {
                return Object.getOwnPropertyDescriptor(target, property);
            }

            if (isReservedMethodName(property)) {
                return undefined;
            }

            return {
                writable: true,
                configurable: true,
                enumerable: true
            };
        },
    });
}

function inspectProxy() {
    return "ScriptExportsProxy {}";
}

interface RpcController {
    request(operation: string, params: any[]): Promise<any>;
}

enum RpcOperation {
    Ok = "ok",
    Error = "error"
}

function isInternalMessage(message: Message): boolean {
    return isRpcMessage(message) || isLogMessage(message);
}

function isRpcMessage(message: Message): boolean {
    return message.type === MessageType.Send && isRpcSendMessage(message);
}

function isRpcSendMessage(message: SendMessage): boolean {
    const payload = message.payload;
    if (!(payload instanceof Array)) {
        return false;
    }

    return payload[0] === "frida:rpc";
}

function isLogMessage(message: Message): boolean {
    return message.type as string === "log";
}

function log(level: LogLevel, text: string): void {
    switch (level) {
        case LogLevel.Info:
            console.log(text);
            break;
        case LogLevel.Warning:
            console.warn(text);
            break;
        case LogLevel.Error:
            console.error(text);
            break;
    }
}

const reservedMethodNames = new Set<string>([
    "then",
    "catch",
    "finally",
]);

function isReservedMethodName(name: string | number | symbol): boolean {
    return reservedMethodNames.has(name.toString());
}

function noop() {
}
