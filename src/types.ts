export type Entry = {id:string;name:string;path:string;command:string;location:string;signer:string;category:string;vt:string};
export type Finding = {id:string;title:string;severity:string;source:string;version:string|null;evidence:string};
export type Analysis = {tool:string;status:string;detail?:string;version?:string;data?:unknown};
export type AI = {verdict:string;summary:string;reasons:{evidence_id:string;explanation:string}[];limitations:string[];next_steps:string[];provider:string};
export type Scan = {id:string;created_at:string;name:string;path:string;sha256:string;size:number;summary:string;status:string;signature:{status:string;subject?:string;detail?:string};pe:Record<string,unknown>;findings:Finding[];analyzers:Analysis[];ai:AI|null;entry:Entry|null};
export type Status = {version:string;tools:Record<string,{available:boolean;path:string|null}>;codex:{available:boolean;subscription:boolean;detail:string}};
