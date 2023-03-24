type RData = Map<string, string> | Map<string, { txt_data: number[] }>;

interface Answer {
    dns_class: string;
    name_labels: string;
    rdata: RData;
    rr_type: string;
    ttl: number;
}

type Rule = {
    action: unknown;
    domain: string;
    ty: "Deny" | "Allow";
};

interface Request {
    answers: Answer[];
    cached: boolean;
    client: string;
    elapsed: number;
    question: string;
    query_type: string;
    rule: Rule | null;
    status: string;
    timestamp: {
        secs_since_epoch: number;
        nanos_since_epoch: number;
    };
}

type Requests = Request[];

interface Cache {
    hits: number;
    misses: number;
    size: number;
}

interface Average {
    count: number;
    average: number;
}

interface Config {
    filter: { name: string; url: string; enabled: boolean }[];
    schedule: { name: string; schedule: string }[];
    upstream: { ip: string; port: number }[];
}

export type { Answer, Average, Cache, Config, Request, Requests };
