import { VariantDict } from "./protocol";

export interface Process {
    pid: number;
    name: string;
    parameters: VariantDict;
}
