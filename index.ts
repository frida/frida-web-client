import * as clientModule from "./lib/client";
import * as crashModule from "./lib/crash";
import * as processModule from "./lib/process";
import * as scriptModule from "./lib/script";
import * as sessionModule from "./lib/session";

export type Client = clientModule.Client;
export const Client = clientModule.Client;
export type ClientOptions = clientModule.ClientOptions;
export type TransportLayerSecurity = clientModule.TransportLayerSecurity;
export const TransportLayerSecurity = clientModule.TransportLayerSecurity;
export type ProcessQueryOptions = clientModule.ProcessQueryOptions;
export type Scope = clientModule.Scope;
export const Scope = clientModule.Scope;
export type SessionOptions = clientModule.SessionOptions;
export type Realm = clientModule.Realm;
export const Realm = clientModule.Realm;

export type Session = sessionModule.Session;
export const Session = sessionModule.Session;
export type SessionDetachedHandler = sessionModule.SessionDetachedHandler;
export type SessionDetachReason = sessionModule.SessionDetachReason;
export const SessionDetachReason = sessionModule.SessionDetachReason;
export type PeerOptions = sessionModule.PeerOptions;
export type Relay = sessionModule.Relay;
export type RelayKind = sessionModule.RelayKind;
export const RelayKind = sessionModule.RelayKind;

export type Script = scriptModule.Script;
export const Script = scriptModule.Script;
export type ScriptOptions = scriptModule.ScriptOptions;
export type ScriptRuntime = scriptModule.ScriptRuntime;
export const ScriptRuntime = scriptModule.ScriptRuntime;
export type ScriptDestroyedHandler = scriptModule.ScriptDestroyedHandler;
export type ScriptMessageHandler = scriptModule.ScriptMessageHandler;
export type ScriptLogHandler = scriptModule.ScriptLogHandler;
export type Message = scriptModule.Message;
export type MessageType = scriptModule.MessageType;
export const MessageType = scriptModule.MessageType;
export type SendMessage = scriptModule.SendMessage;
export type ErrorMessage = scriptModule.ErrorMessage;
export type ScriptExports = scriptModule.ScriptExports;
export type LogLevel = scriptModule.LogLevel;
export const LogLevel = scriptModule.LogLevel;

export type Process = processModule.Process;
export type Crash = crashModule.Crash;
