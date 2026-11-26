export namespace main {
	
	export class ItemPEMs {
	    certPem: string;
	    fullChainPem: string;
	    csrPem: string;
	    hasKey: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ItemPEMs(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.certPem = source["certPem"];
	        this.fullChainPem = source["fullChainPem"];
	        this.csrPem = source["csrPem"];
	        this.hasKey = source["hasKey"];
	    }
	}
	export class SignCSRRequest {
	    name: string;
	    csrPem: string;
	    issuerId: string;
	    validityDays: number;
	    isCA: boolean;
	    pathLen: number;
	    keyUsages: string[];
	    extKeyUsages: string[];
	    storedCsrId: string;
	
	    static createFrom(source: any = {}) {
	        return new SignCSRRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.csrPem = source["csrPem"];
	        this.issuerId = source["issuerId"];
	        this.validityDays = source["validityDays"];
	        this.isCA = source["isCA"];
	        this.pathLen = source["pathLen"];
	        this.keyUsages = source["keyUsages"];
	        this.extKeyUsages = source["extKeyUsages"];
	        this.storedCsrId = source["storedCsrId"];
	    }
	}
	export class VaultStatus {
	    unlocked: boolean;
	    exists: boolean;
	    path: string;
	
	    static createFrom(source: any = {}) {
	        return new VaultStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.unlocked = source["unlocked"];
	        this.exists = source["exists"];
	        this.path = source["path"];
	    }
	}
	export class VerifyResult {
	    valid: boolean;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new VerifyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.valid = source["valid"];
	        this.message = source["message"];
	    }
	}

}

export namespace pki {
	
	export class SubjectOptions {
	    commonName: string;
	    organization: string;
	    organizationalUnit: string;
	    country: string;
	    state: string;
	    locality: string;
	
	    static createFrom(source: any = {}) {
	        return new SubjectOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.commonName = source["commonName"];
	        this.organization = source["organization"];
	        this.organizationalUnit = source["organizationalUnit"];
	        this.country = source["country"];
	        this.state = source["state"];
	        this.locality = source["locality"];
	    }
	}
	export class CertOptions {
	    name: string;
	    subject: SubjectOptions;
	    keyAlgorithm: string;
	    validityDays: number;
	    pathLen: number;
	    dnsNames: string[];
	    ipAddresses: string[];
	    emailAddresses: string[];
	    uris: string[];
	    keyUsages: string[];
	    extKeyUsages: string[];
	    issuerId: string;
	
	    static createFrom(source: any = {}) {
	        return new CertOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.subject = this.convertValues(source["subject"], SubjectOptions);
	        this.keyAlgorithm = source["keyAlgorithm"];
	        this.validityDays = source["validityDays"];
	        this.pathLen = source["pathLen"];
	        this.dnsNames = source["dnsNames"];
	        this.ipAddresses = source["ipAddresses"];
	        this.emailAddresses = source["emailAddresses"];
	        this.uris = source["uris"];
	        this.keyUsages = source["keyUsages"];
	        this.extKeyUsages = source["extKeyUsages"];
	        this.issuerId = source["issuerId"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CertSummary {
	    commonName: string;
	    subject: string;
	    subjectFields: SubjectOptions;
	    issuer: string;
	    serialHex: string;
	    // Go type: time
	    notBefore: any;
	    // Go type: time
	    notAfter: any;
	    isCA: boolean;
	    pathLen: number;
	    keyAlgorithm: string;
	    keyBits: number;
	    signatureAlgorithm: string;
	    dnsNames: string[];
	    ipAddresses: string[];
	    emailAddresses: string[];
	    uris: string[];
	    keyUsages: string[];
	    extKeyUsages: string[];
	    sha256Fingerprint: string;
	    subjectKeyId: string;
	    authorityKeyId: string;
	
	    static createFrom(source: any = {}) {
	        return new CertSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.commonName = source["commonName"];
	        this.subject = source["subject"];
	        this.subjectFields = this.convertValues(source["subjectFields"], SubjectOptions);
	        this.issuer = source["issuer"];
	        this.serialHex = source["serialHex"];
	        this.notBefore = this.convertValues(source["notBefore"], null);
	        this.notAfter = this.convertValues(source["notAfter"], null);
	        this.isCA = source["isCA"];
	        this.pathLen = source["pathLen"];
	        this.keyAlgorithm = source["keyAlgorithm"];
	        this.keyBits = source["keyBits"];
	        this.signatureAlgorithm = source["signatureAlgorithm"];
	        this.dnsNames = source["dnsNames"];
	        this.ipAddresses = source["ipAddresses"];
	        this.emailAddresses = source["emailAddresses"];
	        this.uris = source["uris"];
	        this.keyUsages = source["keyUsages"];
	        this.extKeyUsages = source["extKeyUsages"];
	        this.sha256Fingerprint = source["sha256Fingerprint"];
	        this.subjectKeyId = source["subjectKeyId"];
	        this.authorityKeyId = source["authorityKeyId"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class InspectResult {
	    type: string;
	    items: CertSummary[];
	    valid: boolean;
	    warning?: string;
	
	    static createFrom(source: any = {}) {
	        return new InspectResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.items = this.convertValues(source["items"], CertSummary);
	        this.valid = source["valid"];
	        this.warning = source["warning"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace vault {
	
	export class VaultItemSummary {
	    id: string;
	    kind: string;
	    name: string;
	    issuerId?: string;
	    // Go type: time
	    createdAt: any;
	    hasKey: boolean;
	    hasCert: boolean;
	    hasCsr: boolean;
	    revoked?: boolean;
	    // Go type: time
	    revokedAt?: any;
	    revokeReason?: number;
	    summary: pki.CertSummary;
	
	    static createFrom(source: any = {}) {
	        return new VaultItemSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.name = source["name"];
	        this.issuerId = source["issuerId"];
	        this.createdAt = this.convertValues(source["createdAt"], null);
	        this.hasKey = source["hasKey"];
	        this.hasCert = source["hasCert"];
	        this.hasCsr = source["hasCsr"];
	        this.revoked = source["revoked"];
	        this.revokedAt = this.convertValues(source["revokedAt"], null);
	        this.revokeReason = source["revokeReason"];
	        this.summary = this.convertValues(source["summary"], pki.CertSummary);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

