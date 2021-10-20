export interface SignalSource {
    addListener(name: string, handler: SignalHandler): void;
    removeListener(name: string, handler: SignalHandler): void;
}

export class Signal<T extends SignalHandler> {
    constructor(private source: SignalSource, private name: string) {
    }

    connect(handler: T): void {
        this.source.addListener(this.name, handler);
    }

    disconnect(handler: T): void {
        this.source.removeListener(this.name, handler);
    }
}

export type SignalHandler = (...args: any[]) => void;

export class SignalAdapter implements SignalSource {
    private proxyHandlers: Map<SignalHandler, SignalHandler> = new Map();

    constructor(protected signalSource: SignalSource) {
    }

    addListener(name: string, handler: SignalHandler): void {
        const proxyHandler = this.getProxy(name, handler);
        if (proxyHandler !== null) {
            this.proxyHandlers.set(handler, proxyHandler);
            this.signalSource.addListener(name, proxyHandler);
        } else {
            this.signalSource.addListener(name, handler);
        }
    }

    removeListener(name: string, handler: SignalHandler): void {
        const proxyHandler = this.proxyHandlers.get(handler);
        this.signalSource.removeListener(name, (proxyHandler !== undefined) ? proxyHandler : handler);
    }

    protected getProxy(name: string, userHandler: SignalHandler): SignalHandler | null {
        return null;
    }
}
