import { VariantDict } from "./protocol";

export interface Crash {
    pid: number;
    processName: string;
    summary: string;
    report: string;
    parameters: VariantDict;
}
